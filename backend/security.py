"""Cryptography, input policy, file validation, rate limiting and lockouts."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from config import settings
from models import Lockout, utcnow

# ---------------------------------------------------------------------------
# Passwords: Argon2id with a fresh random salt per hash (argon2-cffi default)
# ---------------------------------------------------------------------------
_ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2, hash_len=32, salt_len=16)
# Used to spend the same time on unknown usernames, so timing does not reveal which exist.
_DUMMY_HASH = _ph.hash(secrets.token_urlsafe(24))

PASSWORD_RULES = ("At least 12 characters, with an uppercase letter, a lowercase letter, "
                  "a number and a symbol, and not containing your username.")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, stored: str | None) -> bool:
    try:
        return _ph.verify(stored or _DUMMY_HASH, password) and stored is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_problem(password: str, username: str = "") -> str | None:
    if not isinstance(password, str) or len(password) < 12 or len(password) > 128:
        return PASSWORD_RULES
    checks = (r"[A-Z]", r"[a-z]", r"\d", r"[^A-Za-z0-9]")
    if not all(re.search(c, password) for c in checks):
        return PASSWORD_RULES
    if username and username.lower() in password.lower():
        return PASSWORD_RULES
    return None


def generate_strong_password() -> str:
    """Random password that satisfies the policy (used for first-boot seed accounts)."""
    while True:
        p = secrets.token_urlsafe(15) + "!" + secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ") + str(secrets.randbelow(10))
        if password_problem(p) is None:
            return p


# Document passcodes are Argon2id too; a server-side pepper is mixed in first.
def hash_passcode(passcode: str) -> str:
    return _ph.hash(settings.passcode_pepper + passcode)


def verify_passcode(passcode: str, stored: str) -> bool:
    return verify_password(settings.passcode_pepper + passcode, stored)


# ---------------------------------------------------------------------------
# Usernames, contacts, names
# ---------------------------------------------------------------------------
USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,31}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")


def mask_email(e: str) -> str:
    local, _, domain = e.partition("@")
    return (local[:2] + "•••@" + domain) if domain else "•••"


def clean_filename(name: str) -> str:
    name = re.sub(r"^.*[\\/]", "", name or "")
    name = re.sub(r"[^\w. -]", "_", name).strip(" .")
    return name[-80:]


# ---------------------------------------------------------------------------
# JWT session tokens (delivered only as an HttpOnly cookie)
# ---------------------------------------------------------------------------
COOKIE_NAME = "tv_session"
JWT_ALG = "HS256"


def issue_token(user_id: int, token_version: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id), "ver": token_version, "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.session_minutes)).timestamp()),
        "jti": secrets.token_hex(8), "iss": "trustvault",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=JWT_ALG)


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[JWT_ALG], issuer="trustvault",
                          options={"require": ["sub", "ver", "iat", "exp"]})
    except jwt.PyJWTError:
        return None


def set_session_cookie(response, token: str) -> None:
    response.set_cookie(
        COOKIE_NAME, token, max_age=settings.session_minutes * 60, path="/api",
        httponly=True, secure=settings.cookie_secure, samesite="strict",
    )


def clear_session_cookie(response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/api", httponly=True, secure=settings.cookie_secure, samesite="strict")


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------
def client_ip(request: Request) -> str:
    if settings.trusted_proxy:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()[:45]
    return (request.client.host if request.client else "")[:45]


class RateLimiter:
    """Sliding-window limiter. Per process: put a shared limiter (e.g. at the proxy) in front
    when running several API replicas."""

    def __init__(self) -> None:
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window_seconds:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def check(self, key: str, limit: int, window_seconds: int) -> None:
        if not self.allow(key, limit, window_seconds):
            raise HTTPException(429, "Too many requests. Please wait and try again.")


limiter = RateLimiter()


# ---------------------------------------------------------------------------
# Lockouts (sign-in and document passcodes): 5 failures -> 15 minutes
# ---------------------------------------------------------------------------
def _lock_key(kind: str, subject: str, ip: str) -> str:
    return hashlib.sha256(f"{kind}|{subject.lower()}|{ip}".encode()).hexdigest()


def lock_remaining(db: Session, kind: str, subject: str, ip: str) -> int:
    row = db.get(Lockout, _lock_key(kind, subject, ip))
    if row and row.locked_until and row.locked_until > utcnow():
        return int((row.locked_until - utcnow()).total_seconds()) + 1
    return 0


def lock_fail(db: Session, kind: str, subject: str, ip: str) -> None:
    key = _lock_key(kind, subject, ip)
    row = db.get(Lockout, key) or Lockout(key_hash=key, failures=0)
    row.failures += 1
    if row.failures >= settings.lockout_threshold:
        row.locked_until = utcnow() + timedelta(minutes=settings.lockout_minutes)
        row.failures = 0
    db.merge(row)
    db.flush()


def lock_clear(db: Session, kind: str, subject: str, ip: str) -> None:
    row = db.get(Lockout, _lock_key(kind, subject, ip))
    if row:
        db.delete(row)
        db.flush()


# ---------------------------------------------------------------------------
# Upload validation: allow-list, double-extension and magic-byte checks
# ---------------------------------------------------------------------------
ALLOWED_EXT = {"pdf", "txt", "doc", "docx", "jpg", "jpeg", "png", "webp", "svg"}
DANGEROUS_PARTS = {"exe", "js", "html", "htm", "php", "sh", "bat", "cmd", "ps1", "svg", "jar", "msi", "vbs"}
MAGIC = {
    "pdf": b"%PDF", "doc": bytes([0xD0, 0xCF, 0x11, 0xE0]), "docx": b"PK\x03\x04",
    "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff", "png": b"\x89PNG\r\n\x1a\n", "webp": b"RIFF",
}
MIME = {
    "pdf": "application/pdf", "txt": "text/plain; charset=utf-8", "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "webp": "image/webp", "svg": "image/svg+xml",
}
_SVG_START = re.compile(rb"^\s*(<\?xml[^>]*\?>\s*)?(<!--[\s\S]*?-->\s*)*<svg[\s>]", re.I)
_SVG_ACTIVE = re.compile(
    rb"<\s*(script|foreignObject|iframe|object|embed|link|style|animate|set|use|image|a|audio|video)\b"
    rb"|<!(DOCTYPE|ENTITY)|\bon\w+\s*=|javascript:|data:|(?:href|src)\s*=\s*(?![\"']?#)|url\s*\(\s*(?![\"']?#)",
    re.I,
)


def extension(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def validate_upload(name: str, data: bytes) -> str | None:
    """Return a human-readable reason to reject, or None if the file is acceptable."""
    name = clean_filename(name)
    ext = extension(name)
    if not name or ext not in ALLOWED_EXT:
        return f"File type .{ext or '?'} is not allowed."
    if any(part.lower() in DANGEROUS_PARTS for part in name.split(".")[1:-1]):
        return "Disguised double extension."
    if not data:
        return "Empty file."
    if len(data) > settings.max_upload_bytes:
        return "Larger than 10 MiB."
    if ext == "svg":
        if len(data) > 1024 * 1024:
            return "SVG larger than 1 MiB."
        if not _SVG_START.match(data):
            return "Content does not match .svg."
        if _SVG_ACTIVE.search(data):
            return "SVG contains active or external content."
        return None
    if ext == "txt":
        if b"\x00" in data:
            return "Content does not match .txt."
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return "Text files must be UTF-8."
        return None
    if not data.startswith(MAGIC[ext]):
        return f"Content does not match .{ext}."
    if ext == "webp" and data[8:12] != b"WEBP":
        return "Content does not match .webp."
    return None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_hex(key: str, msg: str) -> str:
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()
