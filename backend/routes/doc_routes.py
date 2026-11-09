"""Documents: list, upload, read, download, edit, rename, delete, sharing and passcodes."""
from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from auth import Caller, can, current_user, grant_for, guard, require_roles
from config import settings
from database import get_db
from models import CATEGORIES, Document, DocumentBlob, DocumentGrant, User
from schemas import GrantIn, PasscodeIn, Probe, Rename, TextEdit, TextPage, Unlock
from security import (MIME, clean_filename, extension, hash_passcode, limiter, lock_clear, lock_fail,
                      lock_remaining, sha256_hex, validate_upload, verify_passcode)

router = APIRouter(prefix="/api", tags=["documents"])


def _card(db: Session, c: Caller, d: Document) -> dict:
    g = grant_for(db, d, c.user)
    is_owner = d.owner_id == c.user.id
    return {
        "id": d.ref, "name": d.name, "owner": d.owner.username, "category": d.category,
        "date": d.created_at.date().isoformat(), "size": d.size_bytes, "is_text": d.is_text,
        "sha256": d.sha256, "has_passcode": bool(d.passcode_hash), "owner_blocked": d.owner.is_blocked,
        "access": "owner" if is_owner else (g.level.lower() if g else "metadata only"),
        "can": {p: can(c.user, d, p, g) for p in ("read", "edit", "rename", "own")},
    }


def _check_passcode(db: Session, c: Caller, d: Document, passcode: str | None) -> None:
    """Non-owners must present the document passcode when one is set."""
    if not d.passcode_hash or d.owner_id == c.user.id:
        return
    subject = f"{c.user.id}:{d.id}"
    wait = lock_remaining(db, "passcode", subject, c.ip)
    if wait:
        raise HTTPException(429, "Too many wrong passcodes. Try again later.")
    if not passcode:
        raise HTTPException(428, "Passcode required.")
    if not verify_passcode(passcode, d.passcode_hash):
        lock_fail(db, "passcode", subject, c.ip)
        db.commit()
        c.audit("passcode", "denied", "wrong passcode", doc=d)
        raise HTTPException(403, "Wrong passcode. Recorded.")
    lock_clear(db, "passcode", subject, c.ip)
    c.audit("passcode", "allowed", "unlocked for this request", doc=d)


def _blob(db: Session, d: Document) -> bytes:
    b = db.get(DocumentBlob, d.id)
    if b is None:
        raise HTTPException(404, "Content missing.")
    return b.content


def _file_response(d: Document, data: bytes, download: bool) -> Response:
    ext = extension(d.name)
    mime = "application/octet-stream" if download else MIME.get(ext, "application/octet-stream")
    safe = d.name.encode("ascii", "replace").decode().replace('"', "_")
    return Response(content=data, media_type=mime, headers={
        "Content-Disposition": f'{"attachment" if download else "inline"}; filename="{safe}"',
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; sandbox",
        "Cache-Control": "no-store",
        "X-Document-SHA256": d.sha256,
    })


# ---------------------------------------------------------------------------
# Listing and stats
# ---------------------------------------------------------------------------
@router.get("/documents")
def list_documents(q: str = "", owner: str = "", category: str = "", from_date: date | None = None,
                   c: Caller = Depends(current_user), db: Session = Depends(get_db, scope="function")):
    stmt = select(Document).where(Document.is_deleted.is_(False))
    if c.user.role != "ADMIN":
        granted = select(DocumentGrant.document_id).where(DocumentGrant.user_id == c.user.id)
        stmt = stmt.where(or_(Document.owner_id == c.user.id, Document.id.in_(granted)))
    if q:
        stmt = stmt.where(Document.name.contains(q[:80], autoescape=True))
    if owner:
        stmt = stmt.join(User, User.id == Document.owner_id).where(User.username == owner[:32])
    if category in CATEGORIES:
        stmt = stmt.where(Document.category == category)
    if from_date:
        stmt = stmt.where(Document.created_at >= from_date)
    docs = db.execute(stmt.order_by(Document.id)).unique().scalars().all()
    return {"documents": [_card(db, c, d) for d in docs], "categories": list(CATEGORIES)}


@router.get("/documents/owners")
def document_owners(c: Caller = Depends(current_user), db: Session = Depends(get_db, scope="function")):
    stmt = select(User.username).join(Document, Document.owner_id == User.id).where(Document.is_deleted.is_(False))
    if c.user.role != "ADMIN":
        granted = select(DocumentGrant.document_id).where(DocumentGrant.user_id == c.user.id)
        stmt = stmt.where(or_(Document.owner_id == c.user.id, Document.id.in_(granted)))
    return sorted({r[0] for r in db.execute(stmt.distinct())})


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------
def _store(db: Session, c: Caller, name: str, category: str, data: bytes, is_text: bool) -> Document:
    d = Document(owner_id=c.user.id, name=name, category=category if category in CATEGORIES else "Other",
                 mime_type=MIME.get(extension(name), "application/octet-stream"), is_text=is_text,
                 size_bytes=len(data), sha256=sha256_hex(data))
    db.add(d)
    db.flush()
    db.add(DocumentBlob(document_id=d.id, content=data))
    db.flush()
    db.refresh(d)
    return d


@router.post("/documents", status_code=201)
async def upload(request: Request, file: UploadFile = File(...), category: str = Form("Other"),
                 c: Caller = Depends(require_roles("OWNER")), db: Session = Depends(get_db, scope="function")):
    limiter.check(f"upload:{c.user.id}", 30, 600)
    data = await file.read(settings.max_upload_bytes + 1)
    name = clean_filename(file.filename or "")
    reason = validate_upload(name, data)
    if reason:
        c.audit("upload", "denied", reason)
        raise HTTPException(422, reason)
    d = _store(db, c, name, category, data, is_text=extension(name) == "txt")
    c.audit("upload", "allowed", f"sha256 {d.sha256[:12]}", doc=d)
    return _card(db, c, d)


@router.post("/documents/text", status_code=201)
def create_text(body: TextPage, c: Caller = Depends(require_roles("OWNER")), db: Session = Depends(get_db, scope="function")):
    limiter.check(f"upload:{c.user.id}", 30, 600)
    base = body.name.strip()
    if base.lower().endswith(".txt"):
        base = base[:-4]
    name = clean_filename((base or "note") + ".txt")
    data = body.text.encode("utf-8")
    reason = validate_upload(name, data)
    if reason:
        c.audit("upload", "denied", reason)
        raise HTTPException(422, reason)
    d = _store(db, c, name, body.category, data, is_text=True)
    c.audit("upload", "allowed", "text page", doc=d)
    return _card(db, c, d)


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------
@router.get("/documents/{ref}/metadata")
def metadata(ref: str, c: Caller = Depends(current_user), db: Session = Depends(get_db, scope="function")):
    from auth import load_doc
    d = load_doc(db, ref)
    allowed = d is not None and not d.is_deleted and (c.user.role == "ADMIN" or can(c.user, d, "read", grant_for(db, d, c.user)))
    if not allowed:
        c.audit("metadata", "denied", doc=d, document_ref=(d.ref if d else ref[:16]))
        raise HTTPException(403, "Refused. This attempt has been recorded.")
    c.audit("metadata", "allowed", doc=d)
    card = _card(db, c, d)
    card["grants"] = len(d.grants)
    return card


@router.post("/documents/{ref}/content")
def content(ref: str, body: Unlock, c: Caller = Depends(current_user), db: Session = Depends(get_db, scope="function")):
    d, _ = guard(db, c, ref, "read", "read")
    _check_passcode(db, c, d, body.passcode)
    return _file_response(d, _blob(db, d), download=False)


@router.post("/documents/{ref}/download")
def download(ref: str, body: Unlock, c: Caller = Depends(current_user), db: Session = Depends(get_db, scope="function")):
    d, _ = guard(db, c, ref, "read", "download")
    _check_passcode(db, c, d, body.passcode)
    return _file_response(d, _blob(db, d), download=True)


@router.post("/documents/probe")
def probe(body: Probe, c: Caller = Depends(require_roles("OWNER", "VIEWER")), db: Session = Depends(get_db, scope="function")):
    guard(db, c, body.document_id, "read", "probe")
    return {"readable": True}


# ---------------------------------------------------------------------------
# Change
# ---------------------------------------------------------------------------
@router.put("/documents/{ref}/text")
def edit_text(ref: str, body: TextEdit, c: Caller = Depends(current_user), db: Session = Depends(get_db, scope="function")):
    d, _ = guard(db, c, ref, "edit", "edit", "save")
    if not d.is_text:
        raise HTTPException(422, "Only text documents can be edited here.")
    _check_passcode(db, c, d, body.passcode)
    data = body.text.encode("utf-8")
    if b"\x00" in data:
        raise HTTPException(422, "Text cannot contain NUL bytes.")
    blob = db.get(DocumentBlob, d.id)
    blob.content = data
    d.size_bytes, d.sha256 = len(data), sha256_hex(data)
    db.flush()
    return _card(db, c, d)


@router.patch("/documents/{ref}")
def rename(ref: str, body: Rename, c: Caller = Depends(current_user), db: Session = Depends(get_db, scope="function")):
    new = clean_filename(body.name)
    d0, _ = guard(db, c, ref, "rename", "rename", f"rename → {new}")
    if not new or extension(new) != extension(d0.name):
        raise HTTPException(422, "Name needed, and the file type cannot change.")
    _check_passcode(db, c, d0, body.passcode)
    d0.name = new
    db.flush()
    return _card(db, c, d0)


@router.delete("/documents/{ref}")
def delete_document(ref: str, c: Caller = Depends(current_user), db: Session = Depends(get_db, scope="function")):
    d, _ = guard(db, c, ref, "own", "delete", "soft-deleted")
    d.is_deleted = True
    return {"ok": True}


# ---------------------------------------------------------------------------
# Sharing and passcodes (owner only)
# ---------------------------------------------------------------------------
@router.get("/users/grantable")
def grantable(c: Caller = Depends(require_roles("OWNER")), db: Session = Depends(get_db, scope="function")):
    rows = db.execute(select(User).where(User.id != c.user.id, User.role != "ADMIN",
                                         User.is_blocked.is_(False)).order_by(User.username)).scalars()
    return [{"username": u.username, "role": u.role} for u in rows]


@router.get("/documents/{ref}/grants")
def list_grants(ref: str, c: Caller = Depends(require_roles("OWNER")), db: Session = Depends(get_db, scope="function")):
    from auth import load_doc
    d = load_doc(db, ref)
    if not can(c.user, d, "own", None):
        c.audit("grants", "denied", "needs own", doc=d, document_ref=ref[:16])
        raise HTTPException(403, "Refused. This attempt has been recorded.")
    return {"has_passcode": bool(d.passcode_hash), "grants": [
        {"username": g.user.username, "role": g.user.role, "level": g.level.lower(), "can_rename": g.can_rename}
        for g in d.grants]}


@router.put("/documents/{ref}/grants/{username}")
def put_grant(ref: str, username: str, body: GrantIn, c: Caller = Depends(require_roles("OWNER")),
              db: Session = Depends(get_db, scope="function")):
    target = db.execute(select(User).where(User.username == username[:32])).scalar_one_or_none()
    detail = f"{username[:32]} → {body.level}{' + rename' if body.can_rename else ''}"
    if target is None or target.role == "ADMIN" or target.is_blocked or target.id == c.user.id:
        c.audit("grant", "denied", f"{detail}: invalid grantee", document_ref=ref[:16])
        raise HTTPException(422, "That person cannot be given access.")
    d, _ = guard(db, c, ref, "own", "grant", detail)
    owner_target = target.role == "OWNER"                     # owners only ever get read-only
    g = grant_for(db, d, target) or DocumentGrant(document_id=d.id, user_id=target.id)
    g.level = "READ" if owner_target else body.level.upper()
    g.can_rename = False if owner_target else body.can_rename
    db.merge(g)
    db.flush()
    return {"username": target.username, "level": g.level.lower(), "can_rename": g.can_rename}


@router.delete("/documents/{ref}/grants/{username}")
def revoke(ref: str, username: str, c: Caller = Depends(require_roles("OWNER")), db: Session = Depends(get_db, scope="function")):
    d, _ = guard(db, c, ref, "own", "revoke", username[:32])
    target = db.execute(select(User).where(User.username == username[:32])).scalar_one_or_none()
    g = grant_for(db, d, target) if target else None
    if g:
        db.delete(g)
    return {"ok": True}


@router.put("/documents/{ref}/passcode")
def set_passcode(ref: str, body: PasscodeIn, c: Caller = Depends(require_roles("OWNER")), db: Session = Depends(get_db, scope="function")):
    d, _ = guard(db, c, ref, "own", "passcode", "set")
    d.passcode_hash = hash_passcode(body.passcode)
    return {"has_passcode": True}


@router.delete("/documents/{ref}/passcode")
def remove_passcode(ref: str, c: Caller = Depends(require_roles("OWNER")), db: Session = Depends(get_db, scope="function")):
    d, _ = guard(db, c, ref, "own", "passcode", "removed")
    d.passcode_hash = None
    return {"has_passcode": False}
