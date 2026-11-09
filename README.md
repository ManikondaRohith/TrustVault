# TrustVault - A Secure document sharing Website with Audit Trails

Confidential document sharing with server-enforced permissions, email-verified sign-up and
password reset, and a tamper-resistant audit trail.

* **Backend:** Python FastAPI · SQLAlchemy 2 · MySQL 8.0+ (PyMySQL) · Argon2id · JWT in HttpOnly cookies
* **Frontend:** plain HTML/CSS/JS served by the API, Vanta.js background, strict CSP (no inline code or styles)
* **Ops:** Docker Compose, hash-pinned dependencies, integrity-checked assets, automated security suite

---

## Quick start (Windows, Docker Desktop)

```powershell
# development: codes go to backend\data\otp_outbox.log instead of email
.\start.ps1 -Dev            # add -Test to run the security suite afterwards

# production: first run creates backend\.env and backend\db.env with random secrets, then stops
.\start.ps1
#   fill in SMTP or SendGrid, MAIL_FROM and (optionally) the SEED_*_EMAIL values in backend\.env
.\start.ps1
```

Open **http://localhost:8000**. Stop with `.\start.ps1 -Down`.

**macOS / Linux:** run `pwsh ./start.ps1 -Dev` (PowerShell 7). Or by hand: copy both
`backend/*.env.example` files to `backend/.env` and `backend/db.env`, replace every `__GENERATE__`
with 32+ random characters (`openssl rand -hex 32`), put the MySQL password into `DATABASE_URL`,
then `docker compose up -d --build`. The API container runs as uid 10001 and writes its files
with mode 0600, so read them with `sudo`.

### First sign-in

There are no built-in passwords. On first boot the API gives each seed account a random password,
writes them to `backend/data/initial_credentials.txt` (mode 0600), and forces a password change
at first sign-in. Hand them over securely and **delete that file**.

| Username | Role | Note |
|---|---|---|
| `Manikonda_Rohith` | ADMIN | System administrator |
| `Naveen` | OWNER | Document owner 1 (owns D-1001, D-1003) |
| `Gowtham` | OWNER | Document owner 2 (owns D-1002, D-1004; shares D-1004 read-only with Naveen) |
| `Krishna` | VIEWER | Primary viewer, pre-granted **read** on `D-1001` |
| `Keerthi` | VIEWER | Secondary viewer |

Sign-in is username and password only. Sign-ups are always viewers and must enter a 6-digit code
emailed to them. **Forgot password** on the sign-in page emails a 6-digit code to the account's
registered address (seed accounts need `SEED_*_EMAIL` set to use it), then asks for a new password.

---

## Security design

| Area | What is enforced |
|---|---|
| **Passwords** | 12+ chars with upper, lower, digit and symbol, not containing the username, checked on client *and* server. Argon2id (64 MiB, t=3) with a random salt per hash. Unknown usernames take the same time as wrong passwords. |
| **OTP** | 6 digits from a CSPRNG. Only an HMAC-SHA256 (server pepper) is stored in `otp_codes`, with `expires_at` (5 min), `is_used` (single use) and 5 attempts per code. Codes go out only via SMTP or SendGrid (email). `EXPOSE_DEMO_OTPS = False`, and no response ever contains a code. The `outbox` provider is refused when `APP_ENV=production`. |
| **Sessions** | JWT (HS256, 15-min sliding idle expiry) only in a `tv_session` cookie: `HttpOnly; Secure; SameSite=Strict; Path=/api`. Sign-out, password change, role change, block and reset all bump `token_version`, which kills every older token at once. |
| **CSRF** | Every non-GET `/api` request needs `X-Requested-With: TrustVault`. Foreign `Origin` and `Sec-Fetch-Site: cross-site` are refused, on top of SameSite=Strict. |
| **Brute force** | 5 failures lock that username *from that IP* for 15 minutes (so strangers cannot lock real users out globally), plus per-IP rate limits. Document passcodes get the same treatment. |
| **Authorization** | One function, `auth.can()`, decides every document action using live grants from MySQL. The role is checked on every endpoint. Admins can never hold a grant, so they can never read content. Owner-role grantees are read-only. Blocking an owner locks all their documents for everyone. Missing and forbidden IDs get identical answers (no enumeration). |
| **Uploads** | Allow-list, double-extension block, magic-byte check, UTF-8/NUL check for text, active-content scan for SVG, 10 MiB cap. Files are served with `Content-Security-Policy: sandbox` and `nosniff`. |
| **Browser** | CSP `default-src 'self'` with **no** `'unsafe-inline'` or `'unsafe-eval'`. Fonts, three.js and Vanta are vendored, so there are no CDNs. Also `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP/CORP, HSTS and `Cache-Control: no-store` on the API. |
| **Audit trail** | `audit_logs` is append-only. A `BEFORE INSERT` trigger computes `entry_hash = SHA-256(previous_hash ‖ row)` inside MySQL (replacing pgcrypto). `BEFORE UPDATE` and `BEFORE DELETE` triggers `SIGNAL SQLSTATE '45000'`. The app account may only `SELECT`/`INSERT` that table (`mysql_privileges.sql`), so it cannot `TRUNCATE` it or drop the triggers. Writers serialise on `GET_LOCK` so the chain never forks. Admins can verify the chain and run a live tamper attempt from the UI. |
| **Infrastructure** | MySQL and API bound to `127.0.0.1` only. API container is read-only, has all capabilities dropped, uses `no-new-privileges` and runs as a non-root user. DB secrets live in `db.env`, which the API container never sees. |
| **Supply chain** | `pip install --require-hashes` (448 SHA-256 hashes). `start.ps1` verifies vendored assets against `frontend/assets/checksums.sha256` and pins image digests in `.image-lock.json` on first run (a changed digest stops the start). |

### Production checklist

1. Put a TLS reverse proxy (Caddy, nginx, Traefik) in front of `127.0.0.1:8000`. Set
   `ALLOWED_ORIGINS=https://your-domain`, and `TRUST_PROXY_HEADERS=true` only if the proxy sets `X-Forwarded-For`.
2. Configure real email (SMTP or SendGrid), and keep `APP_ENV=production` (the app refuses unsafe settings at boot).
3. Delete `backend/data/initial_credentials.txt` after handing out the first passwords.
4. Back up the `db_data` volume. Rate limits are per process, so if you run several API replicas,
   add a shared limiter at the proxy.

### Email (Gmail SMTP) and upgrading from the phone/SMS version

* `backend/.env` is pre-filled for Gmail: `EMAIL_PROVIDER=smtp`, `SMTP_HOST=smtp.gmail.com`, port 587 with STARTTLS,
  and a Google **app password** in `SMTP_PASSWORD`. `MAIL_FROM` must be one plain address
  (`trustvault.noreply@gmail.com`); the display name "TrustVault" is added automatically. If you ever revoke the app password,
  create a new one in your Google account and paste it into `SMTP_PASSWORD`.
* The database layout changed (no phone columns, no SMS channel). Use a **fresh database**:
  `.\start.ps1 -Down`, then `docker compose down -v`, then `.\start.ps1`. To keep existing data instead, run
  `backend/migrations/001_email_only.sql` once as the MySQL root user (command inside the file). The API refuses to start
  on an old layout and says so in `docker compose logs api`.

---

## API overview

All endpoints are under `/api`. In development, interactive docs are at `/api/docs`.

| Area | Endpoints |
|---|---|
| Auth | `POST auth/signup/start` · `auth/signup/resend` · `auth/signup/verify` · `auth/login` · `auth/forgot/start` · `auth/forgot/verify` · `auth/forgot/reset` · `auth/logout` · `auth/password` · `GET auth/me` |
| Documents | `GET documents` · `GET documents/owners` · `POST documents` (multipart) · `POST documents/text` · `GET documents/{id}/metadata` · `POST documents/{id}/content` · `POST documents/{id}/download` · `PUT documents/{id}/text` · `PATCH documents/{id}` · `DELETE documents/{id}` · `POST documents/probe` |
| Sharing | `GET users/grantable` · `GET documents/{id}/grants` · `PUT/DELETE documents/{id}/grants/{user}` · `PUT/DELETE documents/{id}/passcode` |
| Admin | `GET admin/users` · `PATCH admin/users/{u}/role` · `POST admin/users/{u}/block`, `/unblock`, `/reset` · `GET admin/reports` · `POST admin/audit/tamper-test` · `POST admin/selftest` |
| Audit | `GET audit` · `GET audit/verify` · `GET stats` |
| Safety | `GET safety/policy` · `GET safety/reportable` · `POST safety/reports` · `POST safety/warnings/ack` · `POST/GET safety/messages` · `GET safety/shared` |

---

## Security test suite

`api_security_check.py` is a black-box suite with 121 checks covering headers, CSP, anonymous access, CSRF,
email codes, cookie flags, OTP exposure and reuse, password policy, role escalation, upload validation, IDOR,
admin content isolation, grants, passcodes, immediate revocation, the blocked-owner cascade, reports
and auto-block, audit visibility, chain verification, trigger and privilege tamper resistance,
brute-force lockout and session revocation. It uses only the standard library.

```powershell
.\start.ps1 -Dev -Test
# or directly:
python api_security_check.py --base http://localhost:8000 `
  --creds backend/data/initial_credentials.txt --outbox backend/data/otp_outbox.log `
  --admin-email manikonda_rohith@trustvault.local
```

It needs a **development** deployment, because it reads codes from the OTP outbox. Never point it at
production. On the first run it changes the admin's forced-reset password and writes the new one
back into the credentials file. Add `--db-url mysql://trustvault:PASS@127.0.0.1:3306/trustvault`
(needs PyMySQL) to also hit the audit table directly with SQL.

---

## Project layout

```
TrustVault_Production/
├── docker-compose.yml        MySQL 8.4 + API, localhost-only ports
├── start.ps1                 integrity checks, secret generation, start-up, health wait
├── api_security_check.py     automated security suite
├── frontend/                 index.html · styles.css · app.js (UI) · vault.js (API client)
│   └── assets/               vendored three.js r134, Vanta NET, Inter font, checksums.sha256
└── backend/
    ├── main.py               app, security middleware, first-boot seed
    ├── config.py             settings + boot-time safety validation
    ├── database.py · models.py · schemas.py
    ├── auth.py               session resolution and the single access function can()
    ├── security.py           Argon2id, JWT cookies, lockouts, rate limits, upload checks
    ├── services/             otp_service.py · audit_service.py
    ├── routes/               auth · doc · admin · safety
    ├── mysql_schema.sql      tables + audit triggers
    ├── mysql_privileges.sql  least-privilege grants for the app account
    ├── Dockerfile · requirements.txt (hash-pinned) · requirements.in
    └── .env.example · db.env.example
```

Third-party assets: GSAP, Vanta.js, Inter(SIL OFL 1.1).
