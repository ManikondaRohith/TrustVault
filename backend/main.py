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
# Demo account bootstrap (safe to run on every startup)
# ---------------------------------------------------------------------------
SEED_USERS = [
    ("Manikonda_Rohith", "Manikonda Rohith", "ADMIN"),
    ("Krishna", "Krishna", "OWNER"),
    ("Naveen", "Naveen", "OWNER"),
    ("Gowtham", "Gowtham", "VIEWER"),
    ("Keerthi", "Keerthi", "VIEWER"),
]
SEED_DOCS = [  # created only on a genuinely empty database
    ("Naveen", "Salary-Letter-Krishna.txt", "HR",
     "Dear Krishna, your revised salary takes effect next month.", {"Krishna": "READ"}),
    ("Gowtham", "Vendor-Contract-Helix.txt", "Contracts", "Helix Ltd. supply agreement. Confidential.", {}),
    ("Naveen", "Q3-Audit-Papers.txt", "Audit", "Working papers for the Q3 regulator review.", {}),
    ("Gowtham", "Partner-Drawings-Rev-C.txt", "Drawings", "Drawing set, revision C. Partner copy.", {"Naveen": "READ"}),
]


def seed() -> None:
    db = SessionLocal()
    try:
        existing_count = db.execute(select(func.count()).select_from(User)).scalar() or 0
        users = {}
        created = []
        for username, display, role in SEED_USERS:
            user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
            if user is None:
                initial_password = settings.demo_initial_password
                if not initial_password:
                    raise RuntimeError("DEMO_INITIAL_PASSWORD is required to create missing demo accounts")
                user = User(
                    username=username, display_name=display, role=role, email=None,
                    password_hash=hash_password(initial_password), is_verified=False, must_reset=True,
                )
                db.add(user)
                created.append(username)
            else:
                # Correct demo roles. A temporary, explicitly enabled flag allows a one-time
                # reset of the five demo passwords without changing email or account identity.
                user.display_name = display
                user.role = role
                if os.getenv("RESET_DEMO_PASSWORDS", "").strip().lower() == "true":
                    reset_password = settings.demo_initial_password
                    if not reset_password:
                        raise RuntimeError("DEMO_INITIAL_PASSWORD is required to reset demo accounts")
                    user.password_hash = hash_password(reset_password)
                    user.must_reset = False
                    user.token_version += 1
            users[username] = user
        db.flush()

        if existing_count == 0:
            for owner, name, cat, content, grants in SEED_DOCS:
                data = content.encode()
                doc = Document(owner_id=users[owner].id, name=name, category=cat,
                               mime_type="text/plain; charset=utf-8", is_text=True,
                               size_bytes=len(data), sha256=sha256_hex(data))
                db.add(doc)
                db.flush()
                db.add(DocumentBlob(document_id=doc.id, content=data))
                for who, level in grants.items():
                    db.add(DocumentGrant(document_id=doc.id, user_id=users[who].id, level=level))
                audit_service.record("system", "upload", "allowed", "seed", document_ref=f"D-{doc.id}",
                                     doc_owner_id=doc.owner_id)
        db.commit()
        if created:
            log.warning("Created %d missing demo accounts with forced password change: %s",
                        len(created), ", ".join(created))
        else:
            log.info("Demo accounts checked; roles are up to date.")
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
