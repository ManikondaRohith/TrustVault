# TrustVault – My Prompts

These are the prompts I used to build TrustVault, from **3 November to 9 November 2026**.
I am writing them the way I actually typed them, so some are short and some have small mistakes.
TrustVault is a website where owners share confidential documents and every touch is recorded.

**Stack I ended up with:** HTML/CSS/JS frontend, FastAPI backend, MySQL 8 database, Docker.
**Roles:** Admin, Owner, Viewer.

---

## Plan of the week

| Day | Prompts | Division |
|---|---|---|
| 3 Nov | #1 – #3 | Planning + Database |
| 4 Nov | #4 – #6 | Backend |
| 5 Nov | #7 – #9 | Security + first Frontend |
| 6 Nov | #10 – #12 | Frontend + Sharing |
| 7 Nov | #13 – #14 | Design (colors, theme, mascot) |
| 8 Nov | #15 – #18 | Safety, Audit, Forgot password |
| 9 Nov | #19 – #22 | Upgrades + Testing + Docker |

---

# DIVISION 1: Planning and Database (3 Nov)

### Prompt #1 – Idea
> I want to make a website called TrustVault to share confidential documents. There should be 3 types of users: Admin, Owner and Viewer. Owner uploads and shares files. Viewer can only open what the owner gives. Admin can see details and the logs but must never read the file content. Tell me the plan and folder structure first, don't write code yet.

**Result:** Folder plan with `frontend/` and `backend/`. Rules for the 3 roles were fixed here.

### Prompt #2 – Database tables
> Use MySQL 8. Make the tables: users, documents, document_blobs (file content in a separate table so the list is fast), document_grants (READ or EDIT for each viewer), reports, messages and audit_logs. Document ids should start from 1001 so they look like D-1001. Give me the full mysql_schema.sql.

**Result:** `mysql_schema.sql` with all tables. Users have `role`, `is_blocked`, `must_reset`, `warnings` columns.

### Prompt #3 – Sample data
> Add 5 sample users: Manikonda_Rohith (Admin), Naveen and Gowtham (Owners), Krishna and Keerthi (Viewers). Also add 4 sample documents. Krishna should already have read access to Salary-Letter-Krishna. Don't hard code passwords, make random ones.

**Result:** Seed code in `main.py`. Passwords are random and saved in `backend/data/initial_credentials.txt`.

---

# DIVISION 2: Backend (4 Nov)

### Prompt #4 – FastAPI setup
> Now make the backend with FastAPI and SQLAlchemy. Files: main.py, config.py, database.py, models.py, schemas.py. Keep settings in a .env file. Unknown fields in requests must be rejected. Errors should be simple messages, no stack trace.

**Result:** App starts, `/api/health` works, errors return plain `{"detail": "..."}`.

### Prompt #5 – Login and sign-up
> Make the auth routes: sign-up, login, logout, me, change password. New sign-ups are always Viewer. Sign-up needs email verification with a 6 digit code. Passwords must be 12+ characters with upper, lower, number and symbol.

**Result:** `routes/auth_routes.py`. Sign-up has start, resend, verify steps.

### Prompt #6 – Document routes
> Make document routes: list, upload, create text page, open, download, edit, rename, delete. Also sharing routes where the owner gives READ or EDIT to a viewer and can take it back. Use one single function to decide who can do what, don't repeat checks everywhere.

**Result:** `routes/doc_routes.py` and the `can()` function in `auth.py`.

---

# DIVISION 3: Security (5 Nov)

### Prompt #7 – Passwords and sessions
> Store passwords with Argon2id. Use JWT in an HttpOnly cookie, not in localStorage. Session should end after 15 minutes of no activity. When user signs out or changes password, all old tokens must stop working.

**Result:** `security.py` with Argon2id and `token_version` to kill old sessions.

### Prompt #8 – OTP and brute force
> Make the OTP safe. Don't store the code, store only a hash. Expiry 5 minutes, one time use, max 5 tries. For login, 5 wrong tries should lock that username for 15 minutes. Add the same lock for document passcodes. Also add CSRF protection.

**Result:** `services/otp_service.py`, `lockouts` table, and the `X-Requested-With: TrustVault` header check.

### Prompt #9 – Upload safety
> Only allow pdf, txt, doc, docx, jpg, png, webp, svg up to 10 MB. Check the real file type and not just the name. Block names like `photo.jpg.exe`. Block scripts inside svg.

**Result:** `validate_upload()` in `security.py`.

---

# DIVISION 4: Frontend (5 to 6 Nov)

### Prompt #10 – Login page
> Make the frontend with plain HTML, CSS and JS only, no frameworks. Login page on the left has a cute document mascot, right side has the form with Sign in and Create account tabs. The mascot should cover its eyes when I type the password and shake when login fails.

**Result:** `index.html` and `styles.css` (login part). See the Login screenshot above.

### Prompt #11 – Dashboard
> After login show a dashboard. Top bar with name, role badge and Sign out. Left menu: Overview, Documents, Safety & Support, Access, Audit trail. Overview has 3 count boxes (documents you can see, refused attempts, audit entries) and a card for each role.

**Result:** `app.js`. The menu changes for each role. Admin does not get the upload button.

### Prompt #12 – Documents page and upload button
> On Documents page show the files as cards with search, owner filter, category filter and a From date. Owner should have a round + button at the bottom right to upload a file or make a text page. Viewer can only Open, Download, and Message owner.

**Result:** Documents grid, filters, and the floating `+` button.

---

# DIVISION 5: Design (7 Nov)

### Prompt #13 – Colors and dark mode
> Make a light and dark theme with a toggle button at the top right. Use CSS variables for all colors. Blue accent, green for OK, red for errors. Dark background should be dark navy.

**Result:** CSS variables in `styles.css` and the sun/moon toggle. First version looks like the picture in **Mistake #1** below.

### Prompt #14 – Background and opening animation
> Add a moving network background on the login page with Vanta.js. Download three.js and Vanta into the project, don't use CDN links. After login play a short book opening animation with a loading bar and then show the dashboard.

**Result:** Vanta net in `assets/vendor/`, and the `.open` book animation.

---

# DIVISION 6: Safety and Audit (8 Nov)

### Prompt #15 – Audit trail
> Every open, download, edit, refused attempt and permission change must be written to an audit table. Nobody should be able to edit or delete it, even the app. Make each row linked to the previous one with a hash so tampering can be found. Add a Verify chain button.

**Result:** `audit_logs` table with MySQL triggers, `audit_service.py`, `mysql_privileges.sql` (app can only SELECT and INSERT there).

### Prompt #16 – Warnings and reports
> Owners should be able to report a viewer who has access to their documents. Each report is 1 warning. When the viewer logs in they must see a big red Warning screen and press "I Understand & Agree". After the 4th warning block the account automatically.

**Result:** `routes/safety_routes.py`, Warning overlay, and the WARNINGS badge. See Warning screenshot in Mistake #8.

### Prompt #17 – Forgot password
> Add Forgot Password on the login page. Steps: enter the registered phone number, send OTP, type the code, then set a new password.

**Result:** First version used a **phone number**. Later I changed it (see Prompt #19 and Mistake #3).

### Prompt #18 – Admin tools
> Admin should be able to change roles, block, unblock and reset users. Add a button "Try to tamper" that tries to change the audit log and shows that it gets refused. Add "Run access self-tests" also.

**Result:** `routes/admin_routes.py` and the Audit trail page buttons.

---

# DIVISION 7: Upgrades, Testing and Docker (9 Nov)

### Prompt #19 – Remove phone, use email only
> Remove the phone number and SMS everywhere. Use only email codes (Gmail SMTP with an app password). Remove the phone columns from the database and give me a migration file for old data. Forgot password should be: email, code, captcha, new password.

**Result:** `migrations/001_email_only.sql`, the 4-step Forgot password box with a captcha.

### Prompt #20 – Docker
> Put everything in Docker Compose: MySQL 8.4 and the API. Ports only on 127.0.0.1. Run the API as a non-root user with read-only files. Make a start.ps1 for Windows that makes the secrets and the .env files for me.

**Result:** `docker-compose.yml`, `backend/Dockerfile`, `start.ps1` with `-Dev`, `-Test`, `-Down`.

### Prompt #21 – Lock the dependencies
> Pin all pip packages with hashes. Make start.ps1 check the three.js, Vanta and font files with a checksum so nobody can swap them. Add strict CSP, no inline scripts or styles.

**Result:** `requirements.txt` with hashes, `checksums.sha256`, CSP in `main.py`.

### Prompt #22 – Security test
> Write a test script that attacks my own website and checks 121 things: headers, CSRF, OTP reuse, role escalation, bad uploads, IDOR, grants, passcodes, blocked owner, audit tampering, lockout and session revoke. Use only Python standard library.

**Result:** `api_security_check.py`, run with `.\start.ps1 -Dev -Test`.

---

# MISTAKES I FOUND (with pictures) AND THE PROMPTS I USED TO FIX THEM

## Mistake #1 – Color palette is broken in light mode
![Light mode login](screenshots/06_Light_Mode_Login.png)

**What is wrong:** The left panel stays dark navy, but the right side is white with a pale blue background. It looks like two different websites stuck together. The heading is also "Welcome back" here, but in dark mode it is "WELCOME BACK".

**My fix prompt:**
> The login page colors don't match in light mode. Left panel is dark navy but the right side is white and light blue. Make both sides follow the same CSS variables so light mode is fully light and dark mode is fully dark. Also keep the heading text the same in both themes.

---

## Mistake #2 – Text is hard to read on the moving background
![Login page dark](screenshots/01_Login_Page.png)

**What is wrong:** The Vanta lines run across the text "Share confidential documents with confidence..." and the last line is hard to read.

**My fix prompt:**
> On the login page the Vanta network lines cross over the tagline text and I can't read it properly. Put a soft dark layer behind the TrustVault title and the tagline, or lower the line opacity in that area. Don't remove the animation.

---

## Mistake #3 – Forgot password box is white and still asks for a phone number
![Forgot password old](screenshots/04_Forgot_Password_Old.png)

**What is wrong (2 things):**
1. The page is dark but the popup is bright white, so the colors don't match.
2. It still says "Enter the phone number registered" and "Send OTP / SMS", but I already decided to use email only.

**My fix prompt:**
> The Forgot password popup is white even in dark mode, make it use the same theme variables as the rest of the site. Also it still asks for phone number and says SMS. Change it to email only: "Enter the email address registered with your account", button "Send code", note "A 6-digit code is sent to your registered email".

---

## Mistake #4 – Old SMS text still on the login page
![Login page dark](screenshots/01_Login_Page.png)

**What is wrong:** The small note under the button says *"Sign-in uses a one-time code sent to your registered email. By default new accounts are viewers who are verified by email and SMS codes."* But sign-in is now only username and password. The code is only for sign-up and forgot password. SMS is gone.

**My fix prompt:**
> The note under Enter the Vault is wrong now. Sign in is only username and password. Change the text to: "Sign in with your username and password. By default new accounts are viewers who are verified by a code sent to their email." Remove the word SMS everywhere in the frontend.

---

## Mistake #5 – OTP email goes to a fake address
![Email OTP](screenshots/02_Email_OTP.png)

**What is wrong:** The code mail came, but below it Gmail shows **"Address not found"**. The code was also sent to `manikonda_rohith@trustvault.local`, and that domain doesn't exist, so it bounced. The seed accounts had no real email.

**My fix prompt:**
> My OTP mail is bouncing with "Address not found" for manikonda_rohith@trustvault.local. The seed users don't have a real email. Make the seed users read their emails from SEED_*_EMAIL in the .env file, and if one is empty then don't try to send a mail, show a clear message "No email registered for this account". Also update the security test so it doesn't use the trustvault.local address.

---

## Mistake #6 – The + button covers the Viewer card
![Owner view](screenshots/03_Owner_View.png)

**What is wrong:** On the Overview page the round **+** button sits on top of the "Viewer" card at the bottom right, so I can't read the end of that card. Also the big box on the left has too much empty space around the small mascot.

**My fix prompt:**
> On Overview the floating + button is covering the Viewer role card. Add bottom padding to the main area so the last cards are never hidden. Also make the big mascot box smaller so the three count boxes on the right line up with it.

---

## Mistake #7 – Date format and category filter on Documents page
![Documents viewer](screenshots/05_Documents_Viewer.png)

**What is wrong (2 things):**
1. The card shows the date as `2026-11-08` but the filter box uses `dd-mm-yyyy`. Two formats on one page is confusing.
2. The second dropdown shows **"Other"** instead of "Any category", so it looks like the filter is already applied and only some files are shown.

**My fix prompt:**
> On the Documents page the card date is yyyy-mm-dd but the From box is dd-mm-yyyy. Show all dates as dd-mm-yyyy. Also the category dropdown shows "Other" by default, it should start on "Any category" and reset when I clear the filters.

---

## Mistake #8 – Warning message wording is confusing
![Warning](screenshots/07_Warning.png)

**What is wrong:** The sentence says *"...is immediately reported to the owner or any inappropriate activities."* That doesn't make sense. Some other texts in my app also have spelling mistakes: "**Atleast** 12 characters", "**inproper** behaviour", "a fourth warning **will blocks** your account".

**My fix prompt:**
> The Warning popup sentence is confusing: "reported to the owner or any inappropriate activities". Rewrite it clearly: "Tampering with documents without the owner's consent is strictly prohibited. This violates vault security, is logged as improper behavior and is reported to the owner." Also fix these spellings in the whole project: "Atleast" → "At least", "inproper" → "improper", "will blocks" → "will block". Search app.js and index.html for any more.

---

## Mistake #9 – Secret files were inside my zip
**What is wrong:** When I zipped the project, `backend/.env` (has my Gmail app password and secret keys) and `backend/data/initial_credentials.txt` (has the first passwords) went inside the zip. `.gitignore` hides them from Git, but the zip does not care about `.gitignore`.

**My fix prompt:**
> Make a small script that creates a clean zip of TrustVault for sharing. It must leave out backend/.env, backend/db.env, backend/data/, .git and any .log files. Also remind me to revoke and make a new Google app password because the old one was in a zip.

---
**Note**: I used AI to generate different approaches of prompts to suit my idea. 
