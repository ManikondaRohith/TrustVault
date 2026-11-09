# PROMPTS.md
## How AI was used on this project, and where it was wrong.

> **Read this first.** These entries are a record of the first working session that produced the initial version (03–09 Nov 2026, with Claude Code, Cursor, Antigravity, Copilot). They describe things that really happened in that session. The week is not over: add your own dated entries as you keep working (what you asked, what came back, what was wrong, the commit that fixed it). Do not leave this as the only record. Before submitting, check each commit link below against your own repository's history.

---

### Context file reused throughout
The challenge brief, supplied as 12 screenshots of the Snovasys problem statement (requirements, the three "non-negotiables", the hand-in list). Everything below was steered by those.

---

### 2026-11-03 - Entry 1: the stack the AI picked could not be installed
* **Asked:** build TrustVault from the brief, "without skipping any requirement".
* **Produced:** a plan on Express + multer + a SQLite npm package.
* **Wrong:** none of it was installable: the sandbox's package registry is blocked (`ENOTFOUND`, then a proxy `403`). Retrying different commands would not have helped.
* **Did instead:** rebuilt the design with zero npm dependencies: Node's built-in `http`, `node:sqlite`, `node:crypto` (and later transitioned to FastAPI with hash-pinned requirements for Python). A side effect I kept on purpose: nothing to supply-chain-attack, and a clean clone runs with no external package download issues.
* **Commit:** `59c8640`

---

### 2026-11-04 - Entry 2 (authorisation): the "who can see this?" SQL did not match the function
* **Asked:** write `authz.js` so one function decides access, plus a SQL fragment for list/search.
* **Produced:** `readableWhere(user)` returning SQL that referenced `:now`, but returning only `{uid}` as parameters. The first draft also forgot that a disabled user must match nothing and still bind both parameters (SQLite rejects unused named parameters).
* **Wrong, specifically:** every list/search call would have thrown, and, worse, the temptation was to "just fix the error" and move on without checking the SQL meant the same thing as `effectivePermission()`. Two independent definitions of "may read" is exactly where a leak hides.
* **Did instead:** changed the signature to `readableWhere(cfg, user)`, bound both parameters in every branch, and wrote an exhaustive test (every user x every document) asserting the SQL and the function agree (`access.test.js`, "exhaustive agreement").
* **Commit:** Fixed before the first commit, so it lands in `59c8640`.

---

### 2026-11-05 - Entry 3 (audit trail): the tamper-detection pointer could lie after a rollback
* **Asked:** an audit trail that "can't be quietly altered", including deletion of the latest rows.
* **Produced:** hash chain + triggers + a separate "head" file written inside `record()`.
* **Wrong, specifically:** `record()` runs inside the caller's database transaction. If the change later rolled back, the head file would already say "entry N" while the database only had N-1, so verification would report tampering that never happened. A noisy false alarm makes people ignore the real one.
* **Did instead:** the head file is written only after the outermost transaction commits (`db.onCommit`). I confirmed it with the "failed change leaves no half-written state" and "truncating the tail is detected" tests. In MySQL V2, tamper resistance was elevated to trigger level (`BEFORE UPDATE`/`DELETE` raise `SIGNAL SQLSTATE '45000'`) with permissions enforced via `mysql_privileges.sql`.
* **Commit:** Fixed before the first commit, so it lands in `59c8640`.

---

### 2026-11-07 - Entry 4 (tests): my own tests failed 7 times for a reason that was not the product
* **Asked:** tests that prove expiry by moving a fake clock forward 31 days.
* **Produced:** a suite that moved the clock, which also made every logged-in session idle out, so later tests got 401 and crashed with confusing undefined errors. It looked like seven real failures.
* **Wrong:** the tests, not the server. I confirmed it by reproducing it in isolation (alice gets 401 after the clock jump and after restoring it) instead of loosening the assertions.
* **Fix:** I found the cause; the suite was then changed (by the time I re-ran it) to use very long sessions for that file, with session timeouts covered by their own dedicated tests in `security.test.js` / `api_security_check.py`.
* **Commit:** `4dc2a01`

---

### 2026-11-09 - Entry 5 (verification): "all tests pass" was not enough
* **Asked:** finish and verify the whole thing.
* **Found:** one failing test (size limit): the server did return 413, but the early body-size check said "limit 1024 bytes" while the validator said "1 KB". Cosmetic, but it showed two code paths owning one message.
* **Did instead:** one shared formatter (`4dc2a01`). Then I did not stop at unit tests: I drove the real UI in a headless browser across all three roles (upload, download, share, expiry on an external share, remove access, assistant, admin verify) and at phone width, and read the console for CSP violations (none). I also re-read all 12 brief screenshots against the build rather than trusting my earlier reading of them.

---

### Where the AI was not the problem, and how I checked it
For the access-control paths I did not take "it passes" on trust. I attacked it as a second user: 404 vs missing-id comparison on every route, a forged edit grant on a viewer, version-number tricks, swapped ciphertext files, edited/deleted/truncated audit rows, and a forged chain without the secret. These are the tests in `access.test.js`, `security.test.js`, `api_security_check.py` (121 checks), and the audit suite.

---

### What the AI-assistant inside the product is allowed to do
**Nothing that changes access.** See `WRITEUP.md`, "Where AI fits".
