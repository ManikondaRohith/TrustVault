<#
.SYNOPSIS
  Start TrustVault with Docker: verify integrity, create secrets, build, run, wait for health.

.DESCRIPTION
  1. Verifies every vendored frontend asset against frontend/assets/checksums.sha256 (SHA-256).
  2. Confirms backend/requirements.txt pins a SHA-256 hash for every package (pip enforces them in the build).
  3. Creates backend/.env and backend/db.env with fresh random secrets if they do not exist.
  4. Pulls images and pins their SHA-256 digests in .image-lock.json on first run; later runs refuse
     to start if a tag suddenly resolves to a different digest (use -UpdateImages to accept).
  5. Builds and starts the stack, then waits for /api/health.

.PARAMETER Dev
  Development mode: one-time codes go to backend/data/otp_outbox.log instead of email,
  seed accounts get placeholder emails, and /api/docs is enabled. Never use for real data.

.PARAMETER Test
  After start-up, run api_security_check.py (needs -Dev and Python 3.9+ on PATH).

.PARAMETER Down
  Stop the stack (data volumes are kept).

.PARAMETER UpdateImages
  Accept new image digests and rewrite .image-lock.json.

.PARAMETER NoDocker
  Only run the integrity checks and create the .env files.

.EXAMPLE
  .\start.ps1 -Dev -Test
#>
[CmdletBinding()]
param(
    [switch]$Dev,
    [switch]$Test,
    [switch]$Down,
    [switch]$UpdateImages,
    [switch]$NoDocker
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
$OnWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ((Get-Variable IsWindows -ErrorAction SilentlyContinue) -and $IsWindows)

function Write-Step([string]$Text) { Write-Host "==> $Text" -ForegroundColor Cyan }
function Fail([string]$Text) { Write-Host "ERROR: $Text" -ForegroundColor Red; exit 1 }

function New-Secret([int]$Bytes = 32) {
    $buf = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buf) } finally { $rng.Dispose() }
    return (($buf | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Write-SecretFile([string]$Path, [string]$Content) {
    [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom)   # no BOM: docker env_file would misread the first key
    if ($OnWindows) {
        & icacls $Path /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
    } else {
        & chmod 600 $Path
    }
}

function Test-Sha256([string]$Path, [string]$Expected) {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    return $actual -eq $Expected.ToLowerInvariant()
}

# Download helper for any future remote dependency: refuses the file unless its SHA-256 matches.
function Get-VerifiedFile([string]$Url, [string]$Destination, [string]$Sha256) {
    $tmp = "$Destination.download"
    Invoke-WebRequest -Uri $Url -OutFile $tmp -UseBasicParsing
    if (-not (Test-Sha256 $tmp $Sha256)) { Remove-Item $tmp -Force; Fail "Checksum mismatch for $Url" }
    Move-Item $tmp $Destination -Force
}

Set-Location $Root

# ---------------------------------------------------------------------------
if ($Down) {
    Write-Step 'Stopping TrustVault (volumes are kept)'
    & docker compose down
    exit $LASTEXITCODE
}
if ($Test -and -not $Dev) { Fail '-Test reads one-time codes from the development outbox, so it needs -Dev.' }

# ---------------------------------------------------------------------------
Write-Step 'Verifying vendored frontend assets (SHA-256)'
$manifest = Join-Path $Root 'frontend/assets/checksums.sha256'
if (-not (Test-Path $manifest)) { Fail "Missing $manifest" }
$count = 0
foreach ($line in Get-Content $manifest) {
    if ($line -match '^\s*$' -or $line.StartsWith('#')) { continue }
    if ($line -notmatch '^([0-9a-fA-F]{64})\s+\*?(.+)$') { Fail "Bad checksum line: $line" }
    $file = Join-Path (Join-Path $Root 'frontend/assets') $Matches[2].Trim()
    if (-not (Test-Sha256 $file $Matches[1])) { Fail "Integrity check failed: $file" }
    $count++
}
Write-Host "    $count files verified"

Write-Step 'Checking that every Python dependency is hash-pinned'
$req = Get-Content (Join-Path $Root 'backend/requirements.txt')
$pkgs = @($req | Where-Object { $_ -match '^[A-Za-z0-9_.\-]+==' })
$hashes = @($req | Where-Object { $_ -match '--hash=sha256:[0-9a-f]{64}' })
if ($pkgs.Count -eq 0 -or $hashes.Count -lt $pkgs.Count) { Fail 'backend/requirements.txt must pin a sha256 hash for every package.' }
Write-Host "    $($pkgs.Count) packages, $($hashes.Count) hashes"

# ---------------------------------------------------------------------------
$envPath = Join-Path $Root 'backend/.env'
$dbEnvPath = Join-Path $Root 'backend/db.env'
$dataDir = Join-Path $Root 'backend/data'
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
if (-not $OnWindows) { & chmod 0733 $dataDir }  # container (uid 10001) must write here; its files are 0600

if (-not (Test-Path $dbEnvPath)) {
    Write-Step 'Creating backend/db.env with random passwords'
    $dbPassword = New-Secret 24
    $db = (Get-Content (Join-Path $Root 'backend/db.env.example') -Raw)
    $db = $db -replace 'MYSQL_ROOT_PASSWORD=__GENERATE__', "MYSQL_ROOT_PASSWORD=$(New-Secret 24)"
    $db = $db -replace 'MYSQL_PASSWORD=__GENERATE__', "MYSQL_PASSWORD=$dbPassword"
    Write-SecretFile $dbEnvPath $db
} else {
    $line = Select-String -Path $dbEnvPath -Pattern '^MYSQL_PASSWORD=(.+)$' | Select-Object -First 1
    if (-not $line) { Fail 'backend/db.env has no MYSQL_PASSWORD' }
    $dbPassword = $line.Matches[0].Groups[1].Value.Trim()
}

if (-not (Test-Path $envPath)) {
    Write-Step "Creating backend/.env ($(if ($Dev) { 'development' } else { 'production' }))"
    $e = Get-Content (Join-Path $Root 'backend/.env.example') -Raw
    foreach ($k in 'JWT_SECRET', 'OTP_PEPPER', 'PASSCODE_PEPPER') { $e = $e -replace "$k=__GENERATE__", "$k=$(New-Secret 32)" }
    $e = $e -replace '__MYSQL_PASSWORD__', $dbPassword
    if ($Dev) {
        $e = $e -replace 'APP_ENV=production', 'APP_ENV=development'
        $e = $e -replace 'EMAIL_PROVIDER=smtp', 'EMAIL_PROVIDER=outbox'
        $e = $e -replace 'RATE_SIGNUP_PER_10MIN=10', 'RATE_SIGNUP_PER_10MIN=100'
        $e = $e -replace 'RATE_LOGIN_PER_MIN=30', 'RATE_LOGIN_PER_MIN=200'
        foreach ($u in 'MANIKONDA_ROHITH', 'NAVEEN', 'GOWTHAM', 'KRISHNA', 'KEERTHI') {
            $e = $e -replace "SEED_${u}_EMAIL=\r?\n", "SEED_${u}_EMAIL=$($u.ToLowerInvariant())@trustvault.local`n"
        }
    }
    Write-SecretFile $envPath $e
    if (-not $Dev) {
        Write-Host '    Fill in SMTP/SendGrid, MAIL_FROM and (optionally) the SEED_*_EMAIL values in backend/.env, then run again.' -ForegroundColor Yellow
        if (-not $NoDocker) { exit 0 }
    }
}

if ($NoDocker) { Write-Step 'Checks done (-NoDocker)'; exit 0 }

# ---------------------------------------------------------------------------
Write-Step 'Checking Docker'
& docker version --format '{{.Server.Version}}' 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { Fail 'Docker is not running. Start Docker Desktop and try again.' }

Write-Step 'Pulling images and checking pinned digests'
$images = @('mysql:8.4', 'python:3.13-slim')
foreach ($img in $images) { & docker pull --quiet $img | Out-Null; if ($LASTEXITCODE -ne 0) { Fail "docker pull $img failed" } }
$lockPath = Join-Path $Root '.image-lock.json'
$current = @{}
foreach ($img in $images) { $current[$img] = (& docker image inspect $img --format '{{index .RepoDigests 0}}').Trim() }
if ((Test-Path $lockPath) -and -not $UpdateImages) {
    $lock = Get-Content $lockPath -Raw | ConvertFrom-Json
    foreach ($img in $images) {
        $pinned = $lock.$img
        if ($pinned -and $pinned -ne $current[$img]) {
            Fail "$img now resolves to $($current[$img]) but $pinned is pinned. Review it, then rerun with -UpdateImages."
        }
    }
    Write-Host '    digests match .image-lock.json'
} else {
    [System.IO.File]::WriteAllText($lockPath, ($current | ConvertTo-Json), $Utf8NoBom)
    Write-Host '    pinned:'; $current.GetEnumerator() | ForEach-Object { Write-Host "      $($_.Value)" }
}

Write-Step 'Building and starting containers'
& docker compose up -d --build
if ($LASTEXITCODE -ne 0) { Fail 'docker compose up failed. See: docker compose logs' }

Write-Step 'Waiting for the API'
$ok = $false
for ($i = 0; $i -lt 60; $i++) {
    try { if ((Invoke-RestMethod -Uri 'http://localhost:8000/api/health' -TimeoutSec 3).status -eq 'ok') { $ok = $true; break } } catch { }
    Start-Sleep -Seconds 3
}
if (-not $ok) { Fail 'API did not become healthy. See: docker compose logs api' }

Write-Host ''
Write-Host 'TrustVault is running at http://localhost:8000' -ForegroundColor Green
$creds = Join-Path $dataDir 'initial_credentials.txt'
if (Test-Path $creds) {
    Write-Host "First-boot passwords: $creds  (each account must change it at first sign-in; delete the file afterwards)" -ForegroundColor Yellow
}
if ($Dev) { Write-Host "Development one-time codes: $(Join-Path $dataDir 'otp_outbox.log')" -ForegroundColor Yellow }

if ($Test) {
    Write-Step 'Running api_security_check.py'
    $py = if (Get-Command python3 -ErrorAction SilentlyContinue) { 'python3' } else { 'python' }
    & $py (Join-Path $Root 'api_security_check.py') --base http://localhost:8000 --creds $creds `
        --outbox (Join-Path $dataDir 'otp_outbox.log') --admin-email 'manikonda_rohith@trustvault.local'
    exit $LASTEXITCODE
}
