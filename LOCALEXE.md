Here's the whole setup from scratch on Windows:

## 1. Install three programs (one time)

| Program | Download | Note |
|---|---|---|
| **Python 3.10 or newer** | python.org/downloads | Tick **"Add python.exe to PATH"** on the first installer screen |
| **Docker Desktop** | docker.com/products/docker-desktop | Accept the WSL 2 option, then restart the PC |
| **VS Code** | code.visualstudio.com | You already have it |

After the restart, open **Docker Desktop** and wait until it says **"Engine running"**.

## 2. Put the project in a simple folder

Extract `TrustVault_Production.zip` to **`C:\TrustVault_Production`**.

Keep it out of `Desktop` and `OneDrive`: OneDrive syncing can lock files while Python installs packages.

## 3. Open it in VS Code

- **File → Open Folder → `C:\TrustVault_Production`**
- **Terminal → New Terminal** (it should be PowerShell)

Check that both tools are installed:

```powershell
python --version
docker --version
```

If either says "not recognized", close and reopen VS Code. If it still fails, reinstall that program.

## 4. Allow the script to run (one time)

```powershell
Get-ChildItem -Recurse | Unblock-File
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

If it asks to confirm, type `Y`.

## 5. Make sure Docker Desktop is running

Look for the whale icon in the taskbar. The script will fail if Docker is installed but not running.

## 6. Start TrustVault

```powershell
.\start.ps1
```

The first run takes 5–10 minutes. The script automatically:
- creates passwords and secret keys
- downloads MySQL and starts it in Docker
- creates the database tables
- installs the Python packages
- starts the website

It's ready when the terminal shows **"Application startup complete"**.

## 7. Open the website

Go to **http://127.0.0.1:8000** in Chrome or Edge.

Always use that exact address. `localhost` or your IP address won't sign you in properly.

## 8. Sign in the first time

1. In VS Code, open **`backend\seed_credentials.txt`**. It lists each username and its temporary password.
2. On the website, enter for example `Naveen` and his password from that file.
3. A code box appears. Find the code in the **terminal**, on a line like:
   ```
   [console email] to=naveen@... purpose=login code=482913
   ```
   Type `482913` into the code box.
4. Choose a new password. It needs 12+ characters with an uppercase letter, a lowercase letter, a number and a symbol, and it must not contain the username.

Do the same for the other accounts:

| Username | Role |
|---|---|
| `Manikonda_Rohith` | ADMIN |
| `Naveen` | OWNER |
| `Gowtham` | OWNER |
| `Krishna` | VIEWER (can read D-1001) |
| `Keerthi` | VIEWER |

When every account has its new password, delete `seed_credentials.txt`.

## 9. Stopping and starting again

**To stop:**
- Website: press `Ctrl + C` in the terminal.
- Database: run `docker compose stop`.

**Next time:** open Docker Desktop, open the folder in VS Code, and run:
```powershell
.\start.ps1
```
After the first time it starts in a few seconds, and your data and passwords are kept.

## 10. Run the security tests (optional)

```powershell
.\start.ps1 -Check
```
You should see **38/38 checks passed**. It uses a temporary copy of the database, so your real data isn't touched.

## Common problems

| Problem | Fix |
|---|---|
| "cannot be loaded… not digitally signed" | Repeat step 4 |
| `docker pull failed` or "pipe not found" | Docker Desktop isn't running. Start it and wait for "Engine running" |
| "port 3306 already in use" | Another MySQL is installed. Run `Stop-Service MySQL80` in an Administrator PowerShell, then try again |
| "port 8000 already in use" | Close the other terminal that's running TrustVault |
| No code box appears / codes rejected | Use the newest code in the terminal. Each code expires after 5 minutes and works only once |
| Want a completely fresh start | Run the commands below |

Fresh start (this **deletes all data**):

```powershell
docker compose down -v
Remove-Item .env, backend\.env, backend\seed_credentials.txt -ErrorAction SilentlyContinue
Remove-Item backend\storage -Recurse -ErrorAction SilentlyContinue
.\start.ps1
```

## Real email and SMS codes (later)

To send codes to real inboxes and phones instead of the terminal, open `backend\.env` and fill in either your SMTP details or a SendGrid key, plus your Twilio details. The README has the exact lines under "Real OTP delivery". Then restart with `.\start.ps1`.

**If you don't install Docker:** `start.ps1` downloads MySQL itself, checks the file is genuine, and runs it privately in your user folder. Docker is still the easier and cleaner option.
