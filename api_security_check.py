#!/usr/bin/env python3
"""TrustVault API security test suite.

Runs black-box authorization and hardening checks against a running TrustVault API.
Standard library only (Python 3.9+). Uses a DEVELOPMENT deployment, because it reads
one-time email codes from the server's OTP outbox file (EMAIL_PROVIDER=outbox).
Never point it at production.

    python api_security_check.py --base http://localhost:8000 \
        --creds backend/data/initial_credentials.txt --outbox backend/data/otp_outbox.log

Optional: --db-url mysql://user:pass@127.0.0.1:3306/trustvault (needs PyMySQL) also checks
that the audit triggers refuse UPDATE/DELETE when issued directly against the database.

On first run the admin seed account is forced to change its password; the suite does that
and writes the new password back into the credentials file.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, info: str = "") -> bool:
    RESULTS.append((name, bool(ok), info))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  [{info}]" if info and not ok else ""))
    return bool(ok)


def section(title: str) -> None:
    print(f"\n== {title}")


# ---------------------------------------------------------------------------
# Minimal HTTP client with manual cookie handling (works over http://localhost
# even though the session cookie is flagged Secure)
# ---------------------------------------------------------------------------
class Resp:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def json(self):
        try:
            return json.loads(self.body.decode() or "null")
        except ValueError:
            return None

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")


class Client:
    def __init__(self, base: str, csrf: bool = True):
        self.base, self.csrf, self.cookie, self.set_cookie_raw = base.rstrip("/"), csrf, None, ""

    def req(self, method, path, json_body=None, data=None, headers=None, raw_cookie=None):
        h = {"Accept": "application/json"}
        if self.csrf:
            h["X-Requested-With"] = "TrustVault"
        if json_body is not None:
            data, h["Content-Type"] = json.dumps(json_body).encode(), "application/json"
        if headers:
            h.update(headers)
        cookie = raw_cookie if raw_cookie is not None else self.cookie
        if cookie:
            h["Cookie"] = f"tv_session={cookie}"
        r = urllib.request.Request(self.base + path, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(r, timeout=30) as resp:
                out = Resp(resp.status, resp.headers, resp.read())
        except urllib.error.HTTPError as e:
            out = Resp(e.code, e.headers, e.read())
        for sc in out.headers.get_all("Set-Cookie") or []:
            if sc.startswith("tv_session="):
                self.set_cookie_raw = sc
                val = sc.split(";", 1)[0].split("=", 1)[1]
                self.cookie = val or None
        return out

    def get(self, p, **k): return self.req("GET", p, **k)
    def post(self, p, body=None, **k): return self.req("POST", p, json_body=body if body is not None else {}, **k)
    def put(self, p, body=None, **k): return self.req("PUT", p, json_body=body if body is not None else {}, **k)
    def patch(self, p, body=None, **k): return self.req("PATCH", p, json_body=body if body is not None else {}, **k)
    def delete(self, p, **k): return self.req("DELETE", p, **k)

    def upload(self, name: str, data: bytes, category="Other"):
        b = "----tv" + secrets.token_hex(8)
        body = (f"--{b}\r\nContent-Disposition: form-data; name=\"category\"\r\n\r\n{category}\r\n"
                f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n").encode() + data + f"\r\n--{b}--\r\n".encode()
        return self.req("POST", "/api/documents", data=body, headers={"Content-Type": f"multipart/form-data; boundary={b}"})


# ---------------------------------------------------------------------------
# OTP outbox reader (development deployments only)
# ---------------------------------------------------------------------------
class Outbox:
    def __init__(self, path):
        self.path = path

    def mark(self) -> int:
        return os.path.getsize(self.path) if os.path.exists(self.path) else 0

    def code_for(self, dest: str, since: int, timeout=10.0) -> str:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(self.path):
                with open(self.path, encoding="utf-8") as f:
                    f.seek(since)
                    found = None
                    for line in f:
                        try:
                            e = json.loads(line)
                        except ValueError:
                            continue
                        if e.get("to", "").lower() == dest.lower():
                            m = re.search(r"\b(\d{6})\b", e.get("body", ""))
                            found = m.group(1) if m else found
                    if found:
                        return found
            time.sleep(0.2)
        raise RuntimeError(f"no OTP for {dest} in {self.path}")


SIX_DIGITS = re.compile(r"(?<!\d)\d{6}(?!\d)")


def login(base, outbox: Outbox, username, password, email) -> Client:
    """Password-only sign-in (no emailed code). `outbox` and `email` are kept for call compatibility."""
    c = Client(base)
    r = c.post("/api/auth/login", {"username": username, "password": password})
    if r.status != 200:
        raise RuntimeError(f"login {username}: {r.status} {r.text}")
    return c


def strong_pw() -> str:
    return "Tv!" + secrets.token_urlsafe(12) + "a9Z"


def signup(base, outbox: Outbox, tag: str):
    uname = f"tv_{tag}_{secrets.token_hex(3)}"
    email, pw = f"{uname}@test.invalid", strong_pw()
    c = Client(base)
    m = outbox.mark()
    r = c.post("/api/auth/signup/start", {"username": uname, "password": pw, "email": email})
    if r.status != 200:
        raise RuntimeError(f"signup {uname}: {r.status} {r.text}")
    ch = r.json()["challenge_id"]
    r = c.post("/api/auth/signup/verify", {"challenge_id": ch, "code": outbox.code_for(email, m)})
    if r.status != 200:
        raise RuntimeError(f"verify {uname}: {r.status} {r.text}")
    return {"username": uname, "password": pw, "email": email, "client": c, "start": r}


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://localhost:8000")
    ap.add_argument("--creds", default="backend/data/initial_credentials.txt")
    ap.add_argument("--outbox", default="backend/data/otp_outbox.log")
    ap.add_argument("--admin-email", default="", help="ignored (sign-in no longer uses an emailed code); kept for old command lines")
    ap.add_argument("--db-url", default="", help="optional mysql://user:pass@host:port/db for trigger checks")
    a = ap.parse_args()
    base, ob = a.base.rstrip("/"), Outbox(a.outbox)
    anon = Client(base)

    # ------------------------------------------------------------------ headers
    section("Transport and browser hardening")
    r = anon.get("/")
    csp = r.headers.get("Content-Security-Policy", "")
    check("index served", r.status == 200)
    check("CSP present without 'unsafe-inline' or 'unsafe-eval'", csp and "unsafe-inline" not in csp and "unsafe-eval" not in csp, csp)
    check("CSP forbids framing and plugins", "frame-ancestors 'none'" in csp and "object-src 'none'" in csp)
    check("nosniff, DENY framing, no-referrer", r.headers.get("X-Content-Type-Options") == "nosniff"
          and r.headers.get("X-Frame-Options") == "DENY" and r.headers.get("Referrer-Policy") == "no-referrer")
    page = r.text + anon.get("/app.js").text + anon.get("/vault.js").text
    check("no demo credential hints in the frontend",
          not re.search(r"vault123|demo accounts|demo inbox|password\s*[:=]\s*['\"][^'\"]{4,}['\"]", page, re.I))
    check("API responses are not cached", anon.get("/api/health").headers.get("Cache-Control") == "no-store")
    check("interactive API docs disabled or dev-only", anon.get("/api/docs").status in (200, 404))

    section("Anonymous access is refused")
    for method, path in [("GET", "/api/documents"), ("GET", "/api/audit"), ("GET", "/api/admin/users"),
                         ("POST", "/api/documents/D-1001/content"), ("GET", "/api/stats"),
                         ("GET", "/api/safety/messages"), ("POST", "/api/admin/selftest")]:
        rr = anon.req(method, path, json_body={} if method == "POST" else None)
        check(f"anonymous {method} {path} -> 401", rr.status == 401, str(rr.status))

    section("CSRF defences")
    rr = Client(base, csrf=False).post("/api/auth/login", {"username": "x", "password": "y"})
    check("state-changing request without X-Requested-With -> 403", rr.status == 403, str(rr.status))
    rr = anon.post("/api/auth/login", {"username": "x", "password": "y"}, headers={"Origin": "https://evil.example"})
    check("foreign Origin -> 403", rr.status == 403, str(rr.status))
    rr = anon.post("/api/auth/login", {"username": "x", "password": "y"}, headers={"Sec-Fetch-Site": "cross-site"})
    check("Sec-Fetch-Site cross-site -> 403", rr.status == 403, str(rr.status))

    # ------------------------------------------------------------------ admin
    section("Seed admin sign-in (password only, no emailed code)")
    creds = {}
    with open(a.creds, encoding="utf-8") as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                u, role, pw = line.rstrip("\n").split("\t")
                creds[u] = (role, pw)
    admin_name = next(u for u, (role, _) in creds.items() if role == "ADMIN")
    admin_pw = creds[admin_name][1]
    adm = Client(base)
    r = adm.post("/api/auth/login", {"username": admin_name, "password": admin_pw})
    check("admin password alone signs in (no second factor)", r.status == 200 and "challenge_id" not in (r.json() or {}), r.text)
    check("login response exposes no OTP", not SIX_DIGITS.search(json.dumps(r.json() or {})))
    check("old sign-in code endpoint is gone", Client(base).post("/api/auth/login/verify", {"challenge_id": str(uuid.uuid4()), "code": "000000"}).status in (404, 405))
    sc = adm.set_cookie_raw.lower()
    check("session cookie is HttpOnly; Secure; SameSite=Strict; Path=/api",
          "httponly" in sc and "secure" in sc and "samesite=strict" in sc and "path=/api" in sc, sc)
    if (r.json().get("user") or {}).get("must_reset"):
        check("must-reset account cannot use the API before changing password", adm.get("/api/documents").status == 403)
        new_pw = strong_pw()
        check("weak new password refused", adm.post("/api/auth/password", {"current_password": admin_pw, "new_password": "short1A!"}).status == 422)
        rr = adm.post("/api/auth/password", {"current_password": admin_pw, "new_password": new_pw})
        check("password changed", rr.status == 200, rr.text)
        with open(a.creds, encoding="utf-8") as f:
            txt = f.read()
        with open(a.creds, "w", encoding="utf-8") as f:
            f.write(txt.replace(f"{admin_name}\tADMIN\t{admin_pw}", f"{admin_name}\tADMIN\t{new_pw}"))
        admin_pw = new_pw
    check("admin reaches the API", adm.get("/api/documents").status == 200)

    # ------------------------------------------------------------------ signup
    section("Sign-up policy and email-code handling")
    c = Client(base)
    for bad, why in [("short1A!", "too short"), ("alllowercase12!", "no uppercase"), ("NoSymbolsHere123", "no symbol"),
                     ("NoDigitsHere!!ab", "no digit")]:
        rr = c.post("/api/auth/signup/start", {"username": "tv_weak_" + secrets.token_hex(2), "password": bad,
                                               "email": f"w{secrets.token_hex(3)}@test.invalid"})
        check(f"password {why} refused", rr.status == 422, str(rr.status))
    rr = c.post("/api/auth/signup/start", {"username": "tv_x", "password": strong_pw(), "email": "a@b.co",
                                           "role": "ADMIN"})
    check("unexpected 'role' field rejected", rr.status == 422, str(rr.status))
    uname = "tv_otp_" + secrets.token_hex(3)
    m = ob.mark()
    rr = c.post("/api/auth/signup/start", {"username": uname, "password": strong_pw(), "email": f"{uname}@test.invalid"})
    check("sign-up start returns no codes", rr.status == 200 and not SIX_DIGITS.search(
        json.dumps({k: v for k, v in rr.json().items() if k != "challenge_id"})), rr.text)
    rr = c.post("/api/auth/signup/verify", {"challenge_id": rr.json()["challenge_id"], "code": "000000"})
    check("wrong sign-up codes refused", rr.status == 400, str(rr.status))
    check("unknown challenge refused", c.post("/api/auth/signup/verify", {"challenge_id": str(uuid.uuid4()),
          "code": "123456"}).status == 410)
    rr = c.post("/api/auth/signup/start", {"username": "tv_ph_" + secrets.token_hex(2), "password": strong_pw(),
                                           "email": f"p{secrets.token_hex(3)}@test.invalid", "phone": "+91 9000000000"})
    check("phone number is no longer accepted at sign-up", rr.status == 422, str(rr.status))

    o1, o2 = signup(base, ob, "own1"), signup(base, ob, "own2")
    v1, v2 = signup(base, ob, "view1"), signup(base, ob, "view2")
    victim = signup(base, ob, "lock")
    check("new sign-ups are always VIEWER", all(x["start"].json()["role"] == "VIEWER" for x in (o1, o2, v1, v2, victim)))

    section("Forgot password (email code only)")
    fp = signup(base, ob, "forgot")
    fc = Client(base)
    m = ob.mark()
    rr = fc.post("/api/auth/forgot/start", {"email": fp["email"]})
    check("forgot-password start accepted", rr.status == 200 and "challenge_id" in (rr.json() or {}), rr.text)
    check("forgot-password start returns no code", not SIX_DIGITS.search(
        json.dumps({k: v for k, v in rr.json().items() if k != "challenge_id"})), rr.text)
    fch, fcode = rr.json()["challenge_id"], ob.code_for(fp["email"], m)
    unk = fc.post("/api/auth/forgot/start", {"email": f"nobody{secrets.token_hex(3)}@test.invalid"})
    check("unknown email gets the same answer (no account enumeration)",
          unk.status == 200 and set(unk.json()) == set(rr.json()), unk.text)
    check("malformed email refused", fc.post("/api/auth/forgot/start", {"email": "not-an-email"}).status == 422)
    check("phone-based reset no longer exists", fc.post("/api/auth/forgot/start", {"phone": "+91 9000000000"}).status == 422)
    fwrong = f"{(int(fcode) + 1) % 1000000:06d}"
    check("wrong reset code refused", fc.post("/api/auth/forgot/verify", {"challenge_id": fch, "code": fwrong}).status == 400)
    check("unknown reset challenge refused", fc.post("/api/auth/forgot/verify", {"challenge_id": str(uuid.uuid4()), "code": fcode}).status == 410)
    check("correct reset code verifies", fc.post("/api/auth/forgot/verify", {"challenge_id": fch, "code": fcode}).status == 200)
    fp_pw = strong_pw()
    check("weak new password refused", fc.post("/api/auth/forgot/reset", {"challenge_id": fch, "code": fcode, "new_password": "short1A!"}).status == 422)
    check("reset with a wrong code refused", fc.post("/api/auth/forgot/reset", {"challenge_id": fch, "code": fwrong, "new_password": fp_pw}).status == 400)
    check("session exists before the reset", fp["client"].get("/api/documents").status == 200)
    rr = fc.post("/api/auth/forgot/reset", {"challenge_id": fch, "code": fcode, "new_password": fp_pw})
    check("password reset with the emailed code", rr.status == 200, rr.text)
    check("reset does not sign anyone in", fc.cookie is None)
    check("reset ends the old session", fp["client"].get("/api/documents").status == 401)
    check("old password no longer works", Client(base).post("/api/auth/login", {"username": fp["username"], "password": fp["password"]}).status == 401)
    check("new password works", Client(base).post("/api/auth/login", {"username": fp["username"], "password": fp_pw}).status == 200)
    check("reset code is single-use", fc.post("/api/auth/forgot/reset", {"challenge_id": fch, "code": fcode, "new_password": strong_pw()}).status == 410)

    section("Role administration")
    for o in (o1, o2):
        rr = adm.patch(f"/api/admin/users/{o['username']}/role", {"role": "OWNER"})
        check(f"admin promotes {o['username'][:10]}… to OWNER", rr.status == 200, rr.text)
    check("admin cannot create another ADMIN", adm.patch(f"/api/admin/users/{v1['username']}/role", {"role": "ADMIN"}).status == 422)
    check("role change ends the old session", o1["client"].get("/api/documents").status == 401)
    O1 = login(base, ob, o1["username"], o1["password"], o1["email"])
    O2 = login(base, ob, o2["username"], o2["password"], o2["email"])
    V1, V2 = v1["client"], v2["client"]

    section("Zero-trust role enforcement")
    check("viewer cannot upload", V1.post("/api/documents/text", {"name": "x", "category": "HR", "text": "x"}).status == 403)
    check("viewer cannot reach admin endpoints", V1.get("/api/admin/users").status == 403)
    check("owner cannot reach admin endpoints", O1.get("/api/admin/users").status == 403)
    check("owner cannot run admin self-tests", O1.post("/api/admin/selftest").status == 403)
    check("viewer cannot file reports", V1.post("/api/safety/reports", {"category": "Other misconduct",
          "viewer": v2["username"], "details": "testing a refused report"}).status == 403)
    check("admin cannot upload", adm.post("/api/documents/text", {"name": "x", "category": "HR", "text": "x"}).status == 403)

    section("Upload validation")
    rr = O1.post("/api/documents/text", {"name": "secret-plan", "category": "HR", "text": "Top secret plan."})
    check("owner creates a text page", rr.status == 201, rr.text)
    doc = rr.json()["id"]
    check("fake PDF (MZ bytes) rejected", O1.upload("invoice.pdf", b"MZ\x90\x00program").status == 422)
    check("double extension rejected", O1.upload("report.php.txt", b"hello").status == 422)
    check("disallowed type rejected", O1.upload("tool.exe", b"MZ").status == 422)
    check("SVG with script rejected", O1.upload("logo.svg", b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>").status == 422)
    check("SVG with event handler rejected", O1.upload("logo.svg", b"<svg onload='x()'></svg>").status == 422)
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
    rr = O1.upload("../../etc/passwd.png", png)
    check("valid PNG accepted, path stripped from name", rr.status == 201 and "/" not in rr.json()["name"], rr.text)
    check("oversized upload refused", O1.upload("big.txt", b"a" * (10 * 1024 * 1024 + 10)).status in (413, 422))

    section("Document authorization")
    check("stranger cannot read", V1.post(f"/api/documents/{doc}/content").status == 403)
    check("stranger does not see it listed", doc not in [d["id"] for d in V1.get("/api/documents").json()["documents"]])
    check("stranger cannot read metadata", V1.get(f"/api/documents/{doc}/metadata").status == 403)
    r_missing, r_forbidden = V1.post("/api/documents/D-999999/content"), V1.post(f"/api/documents/{doc}/content")
    check("missing and forbidden IDs look identical (no enumeration)",
          r_missing.status == r_forbidden.status and r_missing.json() == r_forbidden.json())
    check("malformed ID refused", V1.post("/api/documents/1%20OR%201=1/content").status in (403, 404))
    check("admin sees metadata", adm.get(f"/api/documents/{doc}/metadata").status == 200)
    check("admin cannot read content without a grant", adm.post(f"/api/documents/{doc}/content").status == 403)
    check("admin cannot download content", adm.post(f"/api/documents/{doc}/download").status == 403)
    check("admin cannot be granted access", O1.put(f"/api/documents/{doc}/grants/{admin_name}", {"level": "read"}).status == 422)
    check("admin cannot read seeded D-1001", adm.post("/api/documents/D-1001/content").status == 403)
    check("non-owner cannot share", O2.put(f"/api/documents/{doc}/grants/{v1['username']}", {"level": "read"}).status == 403)

    rr = O1.put(f"/api/documents/{doc}/grants/{v1['username']}", {"level": "read"})
    check("owner grants read", rr.status == 200, rr.text)
    rr = V1.post(f"/api/documents/{doc}/content")
    check("grantee reads content", rr.status == 200 and rr.body == b"Top secret plan.", rr.text)
    check("file response is sandboxed", "sandbox" in rr.headers.get("Content-Security-Policy", ""))
    check("read grant cannot edit", V1.put(f"/api/documents/{doc}/text", {"text": "hacked"}).status == 403)
    check("read grant cannot rename", V1.patch(f"/api/documents/{doc}", {"name": "x.txt"}).status == 403)
    check("grantee cannot delete", V1.delete(f"/api/documents/{doc}").status == 403)
    check("grantee cannot re-share", V1.put(f"/api/documents/{doc}/grants/{v2['username']}", {"level": "read"}).status == 403)
    check("grantee cannot see grant list", V1.get(f"/api/documents/{doc}/grants").status == 403)
    O1.put(f"/api/documents/{doc}/grants/{v1['username']}", {"level": "edit", "can_rename": False})
    check("edit grant can edit", V1.put(f"/api/documents/{doc}/text", {"text": "Revised plan."}).status == 200)
    check("edit without rename flag cannot rename", V1.patch(f"/api/documents/{doc}", {"name": "x.txt"}).status == 403)
    O1.put(f"/api/documents/{doc}/grants/{v1['username']}", {"level": "edit", "can_rename": True})
    check("rename flag allows rename", V1.patch(f"/api/documents/{doc}", {"name": "plan-v2.txt"}).status == 200)
    check("rename cannot change file type", V1.patch(f"/api/documents/{doc}", {"name": "plan.html"}).status == 422)
    rr = O1.put(f"/api/documents/{doc}/grants/{o2['username']}", {"level": "edit", "can_rename": True})
    check("owner-role grantee is stored read-only", rr.status == 200 and rr.json()["level"] == "read" and not rr.json()["can_rename"])
    check("owner-role grantee cannot edit", O2.put(f"/api/documents/{doc}/text", {"text": "x"}).status == 403)

    section("Document passcodes")
    check("passcode under 8 chars refused", O1.put(f"/api/documents/{doc}/passcode", {"passcode": "short"}).status == 422)
    check("owner sets passcode", O1.put(f"/api/documents/{doc}/passcode", {"passcode": "river-stone-42"}).status == 200)
    check("grantee without passcode -> 428", V1.post(f"/api/documents/{doc}/content").status == 428)
    check("wrong passcode -> 403", V1.post(f"/api/documents/{doc}/content", {"passcode": "nope-nope"}).status == 403)
    check("right passcode -> content", V1.post(f"/api/documents/{doc}/content", {"passcode": "river-stone-42"}).status == 200)
    check("owner needs no passcode", O1.post(f"/api/documents/{doc}/content").status == 200)
    O1.delete(f"/api/documents/{doc}/passcode")

    section("Revocation is immediate")
    check("owner revokes", O1.delete(f"/api/documents/{doc}/grants/{v1['username']}").status == 200)
    check("very next request refused", V1.post(f"/api/documents/{doc}/content").status == 403)

    section("Blocked owner cascade")
    O1.put(f"/api/documents/{doc}/grants/{v1['username']}", {"level": "read"})
    check("grantee reads before block", V1.post(f"/api/documents/{doc}/content").status == 200)
    check("admin blocks owner", adm.post(f"/api/admin/users/{o1['username']}/block").status == 200)
    rr = V1.post(f"/api/documents/{doc}/content")
    check("grantee locked out of blocked owner's document", rr.status in (403, 423), str(rr.status))
    check("blocked owner's session ends", O1.get("/api/documents").status in (401, 403))
    rr = Client(base).post("/api/auth/login", {"username": o1["username"], "password": o1["password"]})
    check("blocked owner cannot sign in", rr.status == 403, str(rr.status))
    check("admin unblocks owner", adm.post(f"/api/admin/users/{o1['username']}/unblock").status == 200)
    O1 = login(base, ob, o1["username"], o1["password"], o1["email"])
    check("access returns after unblock", V1.post(f"/api/documents/{doc}/content").status == 200)

    section("Reports, warnings and auto-block")
    rr = O2.post("/api/safety/reports", {"category": "Harassment", "viewer": v2["username"], "details": "no access yet"})
    check("cannot report a viewer without access to your documents", rr.status == 422, str(rr.status))
    O1.put(f"/api/documents/{doc}/grants/{v2['username']}", {"level": "read"})
    d2 = O2.post("/api/documents/text", {"name": "o2-note", "category": "Other", "text": "o2"}).json()["id"]
    O2.put(f"/api/documents/{d2}/grants/{v2['username']}", {"level": "read"})
    for i in range(3):
        rr = O1.post("/api/safety/reports", {"category": "Data misuse", "viewer": v2["username"],
                                              "details": f"report number {i + 1} for testing"})
    check("three reports give three warnings, not blocked", rr.status == 201 and rr.json()["warnings"] == 3 and not rr.json()["blocked"], rr.text)
    check("report rate limit (3/min per owner)", O1.post("/api/safety/reports", {"category": "Other misconduct",
          "viewer": v2["username"], "details": "fourth from same owner"}).status == 429)
    rr = O2.post("/api/safety/reports", {"category": "Other misconduct", "viewer": v2["username"], "details": "fourth warning overall"})
    check("fourth warning blocks the viewer", rr.status == 201 and rr.json()["blocked"], rr.text)
    check("blocked viewer's session ends", V2.get("/api/documents").status in (401, 403))

    section("Messages")
    check("grantee messages the owner", V1.post("/api/safety/messages", {"document_id": doc, "body": "Please extend access."}).status == 201)
    check("non-grantee cannot message about a document", V1.post("/api/safety/messages", {"document_id": "D-1002", "body": "hello there"}).status == 403)
    check("owner sees the message", any(m["from"] == v1["username"] for m in O1.get("/api/safety/messages").json()))

    section("Audit trail")
    ent = V1.get("/api/audit").json()["entries"]
    check("viewer sees only their own trail", ent and all(e["actor"] == v1["username"] for e in ent))
    check("viewer cannot filter by other actors", all(e["actor"] == v1["username"]
          for e in V1.get(f"/api/audit?actor={admin_name}").json()["entries"]))
    ent = O1.get("/api/audit").json()["entries"]
    check("owner sees entries on their documents", any(e["actor"] == v1["username"] for e in ent))
    check("refused attempts are recorded", any(e["result"] == "denied" for e in adm.get("/api/audit?denied_only=true").json()["entries"]))
    rr = adm.get("/api/audit/verify").json()
    check("hash chain verifies end to end", rr["ok"] and rr["entries"] > 10, json.dumps(rr))
    rr = adm.post("/api/admin/audit/tamper-test").json()
    check("database refuses UPDATE and DELETE on audit_logs", rr["protected"], json.dumps(rr["results"]))
    check("chain still intact after tamper attempt", rr["chain"]["ok"])
    check("only admins run the tamper test", O1.post("/api/admin/audit/tamper-test").status == 403)
    if a.db_url:
        try:
            import pymysql
            u = urllib.parse.urlparse(a.db_url)
            cn = pymysql.connect(host=u.hostname, port=u.port or 3306, user=urllib.parse.unquote(u.username or ""),
                                 password=urllib.parse.unquote(u.password or ""), database=u.path.lstrip("/"))
            for sql in ("UPDATE audit_logs SET detail='x' WHERE id=1", "DELETE FROM audit_logs WHERE id=1"):
                try:
                    cn.cursor().execute(sql)
                    cn.commit()
                    check(f"direct SQL refused: {sql.split()[0]}", False, "statement succeeded")
                except pymysql.err.MySQLError as e:
                    # 1142 = privilege denied (least-privilege account), 1644 = trigger SIGNAL
                    check(f"direct SQL refused: {sql.split()[0]}", e.args[0] in (1142, 1644), str(e))
            cn.close()
        except ImportError:
            print("  (PyMySQL not installed; skipping direct database checks)")

    rr = adm.post("/api/admin/selftest").json()
    check(f"server self-tests ({rr['passed']}/{rr['total']})", rr["passed"] == rr["total"])

    section("Brute-force protection")
    vc = Client(base)
    for _ in range(5):
        vc.post("/api/auth/login", {"username": victim["username"], "password": "Wrong-password-1!"})
    rr = vc.post("/api/auth/login", {"username": victim["username"], "password": victim["password"]})
    check("account locked after 5 failures (even with right password)", rr.status == 429, str(rr.status))
    rr = vc.post("/api/auth/login", {"username": "nobody_" + secrets.token_hex(3), "password": "Wrong-password-1!"})
    check("unknown user gets the same message as a wrong password", rr.status == 401 and "Wrong username or password" in rr.text)

    section("Session lifecycle")
    stolen = V1.cookie
    check("sign-out succeeds", V1.post("/api/auth/logout").status == 200)
    check("token from before sign-out is dead", Client(base).get("/api/documents", raw_cookie=stolen).status == 401)
    check("forged token refused", Client(base).get("/api/documents", raw_cookie="eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.").status == 401)
    rr = adm.post(f"/api/admin/users/{v1['username']}/reset")
    check("admin forces a credential reset", rr.status == 200)
    V1b = login(base, ob, v1["username"], v1["password"], v1["email"])
    check("reset account is held until the password changes", V1b.get("/api/documents").status == 403)

    # ------------------------------------------------------------------ summary
    passed = sum(ok for _, ok, _ in RESULTS)
    print(f"\n{passed}/{len(RESULTS)} checks passed")
    for n, ok, info in RESULTS:
        if not ok:
            print(f"  FAILED: {n} {info}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError) as e:
        print(f"\nAborted: {e}")
        sys.exit(2)
