# THREATS.md
### How TrustVault can be attacked, how it defends itself, and what I consciously chose to accept.

## The one rule

> **Only the owner, or someone the owner shared with, can open a document. The admin cannot.**

The danger is not a hacker breaking in. It is a logged-in user asking for a file that isn't theirs. Document ids are guessable (`D-1001`, `D-1002`), so every request is checked again by one function: `backend/auth.py` → `can()` → `guard()`.

## How it defends itself

| Attack | Result | Test (`api_security_check.py`) |
|---|---|---|
| Guess another document's id | `403`, logged. A missing id gives the same answer. | "missing and forbidden IDs look identical (no enumeration)" |
| Viewer tries to edit or share | Refused. Read access stays read. | "read grant cannot edit" |
| Admin tries to read a file | Refused, even with a forged grant. | "admin cannot read content without a grant" |
| Owner revokes access | Refused on the very next request. | "very next request refused" |
| Old session after sign-out | Dead immediately. | "token from before sign-out is dead" |
| Password guessing | 5 failures lock the account for 15 min. | "account locked after 5 failures (even with right password)" |
| Malicious upload | Wrong type, fake content and scripts are rejected. | "SVG with script rejected" |
| CSRF | Blocked by cookie, header and origin checks. | "CSRF defences" |
| Audit log tampering | App can only add rows; each row's hash includes the previous one. | "hash chain verifies end to end" |

## What I accept (not fixed yet)

- **Files are not encrypted at rest.** Database access exposes everything. *Next: encrypt with managed keys.*
- **Audit hash is not keyed.** Someone with MySQL root could rewrite it. *Next: add a secret key and store the latest hash elsewhere.*
- **2FA is an email code only.** *Next: TOTP.*
- **No malware scan on uploads.** *Next: ClamAV.*

## Known problems to fix

1. `X-Forwarded-For` is trusted from the wrong end, so behind a proxy an attacker may fake their IP and dodge the lock-out.
2. `frontend/index.html` has an inline script and style that the CSP should block, plus a fake "Forgot password" widget with no server behind it.

## Gaps in my tests

No test edits an audit row to see if it is caught. No concurrency tests. No XSS payload test. Run the suite with `.\start.ps1 -Dev -Test`.

## Final position

TrustVault enforces one rule well, and checks it on every request. It is not perfectly secure. The weaknesses above are the work I plan to do next.
