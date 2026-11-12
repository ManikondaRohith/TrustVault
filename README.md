<div align="center">

# 🔐 TrustVault

### Zero-trust document sharing with server-enforced permissions and a tamper-evident audit trail

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)
![Render](https://img.shields.io/badge/Deployed%20on-Render-46E3B7?logo=render&logoColor=black)
![Security Checks](https://img.shields.io/badge/security%20checks-121-brightgreen)
![License](https://img.shields.io/badge/status-active-success)

**🌐 Live demo: [trustvault-1-jaid.onrender.com](https://trustvault-1-jaid.onrender.com)**

*Free-tier hosting sleeps when idle, so the first load can take up to a minute.*

</div>

---

## 👀 Try it in 30 seconds

| # | Username | Role | What to try |
|---|---|---|---|
| 1 | `Manikonda_Rohith` | **ADMIN** | Verify the audit chain, run the live tamper test, block or unblock users. The admin can **never** read document content. |
| 2 | `Naveen` | **OWNER** | Upload documents, grant and revoke access, set passcodes |
| 3 | `Krishna` | **OWNER** | Share a document read-only with another owner |
| 4 | `Gowtham` | **VIEWER** | Open a shared document, watch the access get logged |
| 5 | `Keerthi` | **VIEWER** | Try opening something you were never granted and see the identical "not found" answer |

**Password for all demo accounts: `vault@123`**

> ### ⚠️ Disclaimer
> **The email gateway (sign-up OTP and password-reset codes) is temporarily disabled.** My SMTP app password and API key were exposed in a public commit, so I revoked them (the correct response). The replacement credentials set in Render's environment are not being picked up yet, and I am fixing it. The full story is in [Incident report](#-incident-report-leaked-credentials). **Everything except email-based sign-up and forgot-password works, so please use the demo accounts above.**

---

## 📖 What is TrustVault?

Confidential document sharing where **the server decides everything**. Every request is checked against live permissions, access can be revoked instantly, and every action, successful or failed, is written to an **append-only, hash-chained audit log** that the database itself refuses to let anyone edit.

### Why it stands out

| | Feature | Why it matters |
|---|---|---|
| 🛡️ | **Mandatory access control** | One function, `auth.can()`, decides every document action. There are no scattered permission checks to forget. |
| 🕵️ | **Admins cannot read content** | Separation of duties. Administrators manage users but can never hold a grant. |
| ⛓️ | **Tamper-evident audit chain** | Each row stores `SHA-256(previous_hash ‖ row)`, computed **inside the database** by triggers. UPDATE and DELETE are blocked. |
| 💥 | **Live tamper demo** | Admins can attempt to tamper with the log from the UI and watch the database reject it. |
| ⚡ | **Instant revocation** | Grants are read live on every request, and a `token_version` bump kills all older sessions at once. |
| 🙈 | **No enumeration** | Missing and forbidden document IDs return identical responses. |
| 🧪 | **121 automated security checks** | A black-box suite using only the Python standard library. |
| 🔒 | **Strict CSP** | No inline code or styles, and no CDNs. Every asset is vendored and integrity-checked. |

---

## 🧰 Tech stack

| Layer | Technology |
|---|---|
| **Backend** | Python · FastAPI · SQLAlchemy 2 · Pydantic |
| **Database** | **PostgreSQL** (migrated from MySQL 8, see [migration notes](#-mysql--postgresql-migration)) with PL/pgSQL audit triggers |
| **Auth & crypto** | Argon2id · JWT in HttpOnly cookies · HMAC-SHA256 OTPs · SHA-256 hash chain |
| **Frontend** | Plain HTML / CSS / JavaScript served by the API · Vanta.js + three.js background · Inter font |
| **Email** | SMTP (Gmail) or SendGrid, configured through environment variables |
| **Ops** | Docker Compose · hash-pinned dependencies · integrity-checked assets · Render deployment |
| **Testing** | Custom black-box security suite (`api_security_check.py`, 121 checks) |

---

## 📸 Screenshots

> Save your screenshots in `docs/screenshots/` using the file names below, and they will appear automatically.

### 1. Authentication

| Sign in | Sign up with OTP verification |
|:---:|:---:|
| ![Login page](https://github.com/ManikondaRohith/TrustVault/blob/master/SCREENSHOTS/Login.png) | ![Sign-up OTP](https://github.com/ManikondaRohith/TrustVault/blob/master/SCREENSHOTS/Sign%20up.png) |
| **01 · Login page** | **02 · Sign-up with email code** |

| Forgot password | Forced password change |
|:---:|:---:|
| ![Forgot password](https://github.com/ManikondaRohith/TrustVault/blob/master/SCREENSHOTS/Email%20Verification.png) | ![Blocked by Admin](https://github.com/ManikondaRohith/TrustVault/blob/master/SCREENSHOTS/Blocked%20Account.png) |
| **03 · Password reset flow** | **04 · First sign-in Blocked by Admin** |

### 2. Documents and sharing

| Owner dashboard | Upload |
|:---:|:---:|
| ![Owner dashboard](https://github.com/ManikondaRohith/TrustVault/blob/master/SCREENSHOTS/Owner%20View.png) | ![Upload document](https://github.com/ManikondaRohith/TrustVault/blob/master/SCREENSHOTS/Access%20Control%20(Owner).png) |
| **05 · Owner dashboard** | **06 · Secure upload and validation** |

| Share and grant access | Passcode protection |
|:---:|:---:|
| ![Grant access](https://github.com/ManikondaRohith/TrustVault/blob/master/SCREENSHOTS/Access%20Control%20(Owner).png) | ![Direct message](https://github.com/ManikondaRohith/TrustVault/blob/master/SCREENSHOTS/Direct%20Message.png) |
| **07 · Grant or revoke access** | **08 · Document passcode** |

| Viewer dashboard | Document viewer |
|:---:|:---:|
| ![Viewer dashboard](https://github.com/ManikondaRohith/TrustVault/blob/master/SCREENSHOTS/Viewer%20view.png) | ![Document viewer](https://github.com/ManikondaRohith/TrustVault/blob/master/SCREENSHOTS/Documents%20(Viewer).png) |
| **09 · Viewer sees only what is granted** | **10 · Reading a shared document** |

### 3. Admin and audit trail

| Admin console | Audit log |
|:---:|:---:|
| ![Admin console](https://github.com/ManikondaRohith/TrustVault/blob/master/SCREENSHOTS/People%20role%20(Admin).png) | ![Audit log](https://github.com/ManikondaRohith/TrustVault/blob/master/SCREENSHOTS/Admin%20History.png) |
| **11 · User and role management** | **12 · Successful and failed access attempts** |

| Safety and support | Warning |
|:---:|:---:|
| ![Viewer report](https://github.com/ManikondaRohith/TrustVault/blob/master/SCREENSHOTS/Guidelines%20(Viewer).png) | ![Warning](https://github.com/ManikondaRohith/TrustVault/blob/master/SCREENSHOTS/Warning.png) |
| **13 · Hash-chain verified** | **14 · Popped-up warning if reported by owner** |

### 4. Local docker and Email integration

| Local docker running | Email verification |
|:---:|:---:|
| ![Local docker](https://github.com/ManikondaRohith/TrustVault/blob/master/SCREENSHOTS/Docker%20Working.png) | ![Email OTP working](https://github.com/ManikondaRohith/TrustVault/blob/master/SCREENSHOTS/Screenshot%202026-11-12%20193229.png) |
| **15 · 121 security checks passing** | **SMTP Email gateway** |

---

## 🏗️ Architecture

```mermaid
flowchart LR
    U[Browser<br/>HTML/CSS/JS + strict CSP] -->|HTTPS + HttpOnly cookie| API[FastAPI]
    API --> M[Security middleware<br/>CSRF · rate limit · headers]
    M --> A[auth.can<br/>single access decision]
    A --> DB[(PostgreSQL)]
    API --> O[OTP service<br/>HMAC-SHA256]
    O -->|SMTP / SendGrid| E[Email]
    API --> L[Audit service]
    L --> DB
    DB --> T{{Triggers<br/>hash-chain INSERT<br/>block UPDATE / DELETE}}
```

---

## 🔒 Security design

| Area | What is enforced |
|---|---|
| **Passwords** | 12+ chars with upper, lower, digit and symbol, not containing the username, checked on client *and* server. Argon2id (64 MiB, t=3) with a random salt per hash. Unknown usernames take the same time as wrong passwords. |
| **OTP** | 6 digits from a CSPRNG. Only an HMAC-SHA256 (server pepper) is stored, with `expires_at` (5 min), single use and 5 attempts per code. Codes go out only via SMTP or SendGrid. No response ever contains a code, and the `outbox` provider is refused when `APP_ENV=production`. |
| **Sessions** | JWT (HS256, 15-min sliding idle expiry) only in a `tv_session` cookie: `HttpOnly; Secure; SameSite=Strict; Path=/api`. Sign-out, password change, role change, block and reset all bump `token_version`, which kills every older token at once. |
| **CSRF** | Every non-GET `/api` request needs `X-Requested-With: TrustVault`. Foreign `Origin` and `Sec-Fetch-Site: cross-site` are refused, on top of SameSite=Strict. |
| **Brute force** | 5 failures lock that username *from that IP* for 15 minutes (strangers cannot lock real users out globally), plus per-IP rate limits. Document passcodes get the same treatment. |
| **Authorization** | `auth.can()` decides every document action using live grants. The role is checked on every endpoint. Admins can never hold a grant, so they can never read content. Owner-role grantees are read-only. Blocking an owner locks all their documents for everyone. |
| **Uploads** | Allow-list, double-extension block, magic-byte check, UTF-8/NUL check for text, active-content scan for SVG, 10 MiB cap. Files are served with `Content-Security-Policy: sandbox` and `nosniff`. |
| **Browser** | CSP `default-src 'self'` with **no** `'unsafe-inline'` or `'unsafe-eval'`. Fonts, three.js and Vanta are vendored. Also `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP/CORP, HSTS and `Cache-Control: no-store` on the API. |
| **Audit trail** | `audit_logs` is append-only. A `BEFORE INSERT` trigger computes `entry_hash = SHA-256(previous_hash ‖ row)` inside PostgreSQL. `BEFORE UPDATE` and `BEFORE DELETE` triggers raise an exception. The app role may only `SELECT`/`INSERT` that table, so it cannot `TRUNCATE` it or drop the triggers. Writers are serialised with a PostgreSQL advisory lock so the chain never forks. Admins can verify the chain and run a live tamper attempt from the UI. |
| **Infrastructure** | Database and API bound to `127.0.0.1` locally. API container is read-only, has all capabilities dropped, uses `no-new-privileges` and runs as a non-root user. DB secrets live in `db.env`, which the API container never sees. |
| **Supply chain** | `pip install --require-hashes` (448 SHA-256 hashes). `start.ps1` verifies vendored assets against `frontend/assets/checksums.sha256` and pins image digests in `.image-lock.json` on first run (a changed digest stops the start). |

---

## 🐘 MySQL → PostgreSQL migration

TrustVault started on MySQL 8 and now runs on **PostgreSQL**, which is a better fit for Render's managed hosting and for the audit design. The hard part was not the tables, it was re-implementing the guarantees the database enforces.

| Concern | MySQL version | PostgreSQL version |
|---|---|---|
| Driver / URL | `mysql+pymysql://` | `postgresql://` |
| Audit hash | Trigger computing SHA-256 | PL/pgSQL trigger computing SHA-256 |
| Block UPDATE / DELETE | `SIGNAL SQLSTATE '45000'` | `RAISE EXCEPTION` in `BEFORE UPDATE/DELETE` triggers |
| Serialising chain writers | `GET_LOCK()` | `pg_advisory_xact_lock()` |
| Least privilege | `GRANT SELECT, INSERT` | `GRANT SELECT, INSERT` plus `REVOKE UPDATE, DELETE, TRUNCATE` |
| Auto-increment | `AUTO_INCREMENT` | `GENERATED ... AS IDENTITY` |
| Booleans / timestamps | `TINYINT(1)` / `DATETIME` | `BOOLEAN` / `TIMESTAMPTZ` |
| Compose image | `mysql:8.4` | `postgres` |

**Result:** all 121 security checks were re-run against the PostgreSQL build, including trigger tamper resistance and privilege checks.

---

## 🚨 Incident report: leaked credentials

I am documenting this honestly because handling it well matters more than pretending it never happened.

**What happened**
1. My SMTP app password and an email API key were uploaded to a public repository.
2. The leak was detected and the credentials were **revoked immediately**. Revoking is always the right first move, because anything pushed to a public repo is compromised no matter how fast you delete it.
3. I generated new credentials and updated the **environment variables on Render**, but the deployed service still sends mail with the old, revoked values, so OTP emails fail.

**Impact**
- Sign-up OTP and forgot-password emails are unavailable on the live site.
- Demo accounts work normally, and no user data was exposed. Only email-sending credentials leaked.

**Fix in progress**
- [x] Revoke the exposed SMTP password and API key
- [x] Create replacement credentials
- [ ] Update `SMTP_PASSWORD` / API key in Render, then **trigger a manual redeploy**, because Render does not apply changed env vars to a running instance until it restarts
- [ ] Check for stray spaces or newlines in the pasted value. Gmail shows app passwords in groups of four, and they must be pasted **without spaces**
- [ ] Confirm the variable names match `config.py` exactly (`EMAIL_PROVIDER`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `MAIL_FROM`)
- [ ] Confirm no `.env` file baked into the Docker image is overriding Render's values (see `.dockerignore`)
- [ ] Purge the secret from git history (`git filter-repo` or BFG), then force-push

**Lessons applied**
- `.env` and `db.env` are in `.gitignore` and `.dockerignore`. Only `*.env.example` files are committed.
- Secrets are injected through environment variables at deploy time, never stored in code.
- GitHub secret scanning and push protection should be enabled on every repository.
- Production refuses to boot with unsafe settings (`APP_ENV=production` validation in `config.py`).

---

## ✨ Features

- **Email-verified sign-up** and **forgot password** with 6-digit single-use codes
- **Role-based access:** ADMIN, OWNER, VIEWER, with server-side enforcement on every endpoint
- **Document upload** (files and text) with deep validation
- **Granular sharing:** per-user read grants, optional passcodes, instant revocation
- **Safety tooling:** reports, warnings, auto-block, and in-app messages
- **Admin console:** role changes, block/unblock, forced reset, reports, chain verification, tamper test, self-test
- **Live audit log** visible to the right people, with failed attempts recorded too

---

## 🚀 Quick start

### Windows (Docker Desktop)

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
with 32+ random characters (`openssl rand -hex 32`), put the PostgreSQL password into `DATABASE_URL`,
then `docker compose up -d --build`.

### First sign-in (local)

There are no built-in passwords. On first boot the API gives each seed account a random password,
writes them to `backend/data/initial_credentials.txt` (mode 0600), and forces a password change
at first sign-in. Hand them over securely and **delete that file**.

| Username | Role | Note |
|---|---|---|
| `Manikonda_Rohith` | ADMIN | System administrator |
| `Naveen` | OWNER | Owns D-1001, D-1003 |
| `Krishna` | OWNER | Owns D-1002, D-1004 (shares D-1004 read-only with Naveen) |
| `Gowtham` | VIEWER | Pre-granted **read** on `D-1001` |
| `Keerthi` | VIEWER | Secondary viewer |

### Deploy to Render

1. Create a **PostgreSQL** instance on Render and copy its internal `DATABASE_URL`.
2. Create a **Web Service** from this repo (Docker).
3. Add the environment variables: `DATABASE_URL`, `APP_ENV=production`, `JWT_SECRET`, `OTP_PEPPER`, `ALLOWED_ORIGINS`, and the email settings.
4. After **any** env var change, use **Manual Deploy → Deploy latest commit** so the new values load.

### Production checklist

1. Serve over TLS and set `ALLOWED_ORIGINS=https://your-domain`. Set `TRUST_PROXY_HEADERS=true` only if the proxy sets `X-Forwarded-For`.
2. Configure real email (SMTP or SendGrid) and keep `APP_ENV=production`.
3. Delete `backend/data/initial_credentials.txt` after handing out the first passwords.
4. Back up the database. Rate limits are per process, so with several replicas add a shared limiter at the proxy.
5. **Never commit secrets.** Rotate immediately if one leaks.

---

## 📡 API overview

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

## 🧪 Security test suite

`api_security_check.py` is a black-box suite with **121 checks** covering headers, CSP, anonymous access, CSRF,
email codes, cookie flags, OTP exposure and reuse, password policy, role escalation, upload validation, IDOR,
admin content isolation, grants, passcodes, immediate revocation, the blocked-owner cascade, reports
and auto-block, audit visibility, chain verification, trigger and privilege tamper resistance,
brute-force lockout and session revocation. It uses only the standard library.

```powershell
.\start.ps1 -Dev -Test
# or directly:
python api_security_check.py --base http://localhost:8000 `
  --creds backend/data/initial_credentials.txt --outbox backend/data/otp_outbox.log `
  --admin-email manikondarohith2005@gmail.com
```

It needs a **development** deployment, because it reads codes from the OTP outbox. **Never point it at production.**
Add `--db-url postgresql://trustvault:PASS@127.0.0.1:5432/trustvault` to also hit the audit table directly with SQL.

---

## 📁 Project layout

```
TrustVault/
├── docker-compose.yml        PostgreSQL + API, localhost-only ports
├── start.ps1                 integrity checks, secret generation, start-up, health wait
├── api_security_check.py     automated security suite
├── frontend/                 index.html · styles.css · app.js (UI) · vault.js (API client)
│   └── assets/               vendored three.js, Vanta NET, Inter font, checksums.sha256
└── backend/
    ├── main.py               app, security middleware, first-boot seed
    ├── config.py             settings + boot-time safety validation
    ├── database.py · models.py · schemas.py
    ├── auth.py               session resolution and the single access function can()
    ├── security.py           Argon2id, JWT cookies, lockouts, rate limits, upload checks
    ├── services/             otp_service.py · audit_service.py
    ├── routes/               auth · doc · admin · safety
    ├── schema.sql            tables + audit triggers (PostgreSQL)
    ├── privileges.sql        least-privilege grants for the app role
    ├── Dockerfile · requirements.txt (hash-pinned) · requirements.in
    └── .env.example · db.env.example
```

---

## 🗺️ Roadmap

- [ ] Restore the email gateway on Render with rotated credentials
- [ ] Purge leaked secrets from git history and enable push protection
- [ ] Shared rate limiter (Redis) for multi-replica deployments
- [ ] Optional TOTP two-factor authentication
- [ ] Per-document expiry and download limits

---

## 👤 Author

**Manikonda Rohith**
GitHub: [@ManikondaRohith](https://github.com/ManikondaRohith)

*Built to demonstrate secure-by-design engineering: least privilege, defence in depth, verifiable audit trails, and honest incident handling.*

Third-party assets: GSAP, Vanta.js, three.js, Inter (SIL OFL 1.1).
