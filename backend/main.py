"""TrustVault Enterprise V2 — FastAPI application entry point.

    uvicorn main:app --host 0.0.0.0 --port 8000 --proxy-headers
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from starlette.exceptions import HTTPException as StarletteHTTPException

from config import settings
from database import SessionLocal, check_schema
from models import Document, DocumentBlob, DocumentGrant, User
from routes import admin_routes, auth_routes, doc_routes, safety_routes
from security import generate_strong_password, hash_password, sha256_hex
from services import audit_service

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("trustvault")

CSRF_HEADER, CSRF_VALUE = "x-requested-with", "TrustVault"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' blob: data:; "
       "connect-src 'self'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; "
       "frame-ancestors 'none'")

# ---------------------------------------------------------------------------
# Seed data (first boot only)
# ---------------------------------------------------------------------------
SEED_USERS = [
    ("Manikonda_Rohith", "Manikonda Rohith", "ADMIN"),
    ("Naveen", "Naveen", "OWNER"),
    ("Gowtham", "Gowtham", "OWNER"),
    ("Krishna", "Krishna", "VIEWER"),
    ("Keerthi", "Keerthi", "VIEWER"),
]
SEED_DOCS = [  # (owner, name, category, text, grants)
    ("Naveen", "Salary-Letter-Krishna.txt", "HR",
     "Dear Krishna, your revised salary takes effect next month.", {"Krishna": "READ"}),
    ("Gowtham", "Vendor-Contract-Helix.txt", "Contracts", "Helix Ltd. supply agreement. Confidential.", {}),
    ("Naveen", "Q3-Audit-Papers.txt", "Audit", "Working papers for the Q3 regulator review.", {}),
    ("Gowtham", "Partner-Drawings-Rev-C.txt", "Drawings", "Drawing set, revision C. Partner copy.", {"Naveen": "READ"}),
]


def seed() -> None:
    db = SessionLocal()
    try:
        if db.execute(select(func.count()).select_from(User)).scalar():
            return
        creds, users = [], {}
        for username, display, role in SEED_USERS:
            pw = generate_strong_password()
            email = settings.seed_emails.get(username, "")
            u = User(username=username, display_name=display, role=role, email=email.lower() or None,
                     password_hash=hash_password(pw), is_verified=bool(email), must_reset=True)
            db.add(u)
            users[username] = u
            creds.append(f"{username}\t{role}\t{pw}")
        db.flush()
        for owner, name, cat, text, grants in SEED_DOCS:
            data = text.encode()
            d = Document(owner_id=users[owner].id, name=name, category=cat, mime_type="text/plain; charset=utf-8",
                         is_text=True, size_bytes=len(data), sha256=sha256_hex(data))
            db.add(d)
            db.flush()
            db.add(DocumentBlob(document_id=d.id, content=data))
            for who, level in grants.items():
                db.add(DocumentGrant(document_id=d.id, user_id=users[who].id, level=level))
            audit_service.record("system", "upload", "allowed", "seed", document_ref=f"D-{d.id}",
                                 doc_owner_id=d.owner_id)
        db.commit()

        # One-time passwords for the seed accounts: written to a 0600 file, never to the browser.
        # Each account must choose a new password at first sign-in. Delete the file afterwards.
        path = settings.initial_credentials_file
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("# TrustVault first-boot credentials. Every account must change its password at first\n"
                    "# sign-in. DELETE THIS FILE once the accounts have been handed over.\n")
            f.write("\n".join(creds) + "\n")
        log.warning("Seeded %d accounts. One-time passwords written to %s (mode 0600).", len(creds), path)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate()
    check_schema()
    seed()
    yield


app = FastAPI(
    title="TrustVault API", version="2.0.0", lifespan=lifespan,
    docs_url=None if settings.is_production else "/api/docs", redoc_url=None,
    openapi_url=None if settings.is_production else "/api/openapi.json",
)


# ---------------------------------------------------------------------------
# Middleware: CSRF/origin checks and security headers
# ---------------------------------------------------------------------------
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and request.method not in SAFE_METHODS:
        if request.headers.get(CSRF_HEADER) != CSRF_VALUE:
            return JSONResponse({"detail": "Missing or invalid X-Requested-With header."}, status_code=403)
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/") not in settings.allowed_origins:
            return JSONResponse({"detail": "Cross-origin request refused."}, status_code=403)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "Cross-site request refused."}, status_code=403)
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > settings.max_upload_bytes + 64 * 1024:
            return JSONResponse({"detail": "Request too large."}, status_code=413)

    response = await call_next(request)

    h = response.headers
    h.setdefault("Content-Security-Policy", CSP)
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    if settings.cookie_secure:
        h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    if path.startswith("/api/"):
        h["Cache-Control"] = "no-store"
    return response


# ---------------------------------------------------------------------------
# Errors: plain {"detail": "..."} bodies, no stack traces
# ---------------------------------------------------------------------------
@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    first = exc.errors()[0] if exc.errors() else {}
    field = ".".join(str(p) for p in first.get("loc", [])[1:]) or "request"
    return JSONResponse({"detail": f"Invalid {field}: {first.get('msg', 'bad value')}"}, status_code=422)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    log.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse({"detail": "Something went wrong. The error has been logged."}, status_code=500)


@app.get("/api/health")
def health():
    return {"status": "ok"}


for r in (auth_routes.router, doc_routes.router, admin_routes.router, safety_routes.router):
    app.include_router(r)

if os.path.isdir(settings.frontend_dir):
    app.mount("/", StaticFiles(directory=settings.frontend_dir, html=True), name="frontend")
