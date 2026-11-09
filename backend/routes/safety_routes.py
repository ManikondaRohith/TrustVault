"""Safety & support: policy, owner reports (warnings and auto-block), messages, warning acknowledgement."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from auth import Caller, current_user, grant_for, guard, load_doc, require_roles
from config import settings
from database import get_db
from models import Document, DocumentGrant, Message, Report, User
from schemas import MessageIn, ReportIn
from security import limiter
from services import audit_service

router = APIRouter(prefix="/api/safety", tags=["safety"])
WARNING_LIMIT = 3   # the fourth warning blocks the account


@router.get("/policy")
def policy(c: Caller = Depends(current_user)):
    return {
        "allowed_types": [".pdf", ".txt", ".doc", ".docx", ".jpg", ".jpeg", ".png", ".webp", ".svg"],
        "max_upload_mib": settings.max_upload_bytes // (1024 * 1024),
        "session_idle_minutes": settings.session_minutes,
        "lockout": f"{settings.lockout_threshold} attempts / {settings.lockout_minutes} minutes",
        "guest_links": "Disabled",
        "configuration": "Read-only; change through reviewed deployment configuration",
    }


def _viewers_of(db: Session, owner: User) -> list[User]:
    stmt = (select(User).join(DocumentGrant, DocumentGrant.user_id == User.id)
            .join(Document, Document.id == DocumentGrant.document_id)
            .where(Document.owner_id == owner.id, Document.is_deleted.is_(False),
                   User.role == "VIEWER", User.is_blocked.is_(False)).distinct().order_by(User.username))
    return list(db.execute(stmt).scalars())


@router.get("/reportable")
def reportable(c: Caller = Depends(require_roles("OWNER")), db: Session = Depends(get_db, scope="function")):
    return [u.username for u in _viewers_of(db, c.user)]


@router.post("/reports", status_code=201)
def report(body: ReportIn, c: Caller = Depends(require_roles("OWNER")), db: Session = Depends(get_db, scope="function")):
    limiter.check(f"report:{c.user.id}", 3, 60)
    target = next((u for u in _viewers_of(db, c.user) if u.username.lower() == body.viewer.lower()), None)
    if target is None:
        c.audit("report", "denied", f"{body.viewer[:32]} has no access to your documents")
        raise HTTPException(422, "You can report only a viewer who has access to one of your documents.")
    doc = load_doc(db, body.document_id) if body.document_id else None
    if doc is not None and doc.owner_id != c.user.id:
        doc = None
    target = db.get(User, target.id, with_for_update=True)
    db.add(Report(reporter_id=c.user.id, target_id=target.id, document_id=doc.id if doc else None,
                  category=body.category, details=body.details.strip()))
    target.warnings += 1
    c.audit("report", "allowed", f"{body.category} → {target.username}", doc=doc)
    audit_service.record("system", "warning", "allowed", f"{target.username} warning {target.warnings}")
    if target.warnings > WARNING_LIMIT:
        target.is_blocked = True
        target.token_version += 1
        audit_service.record("system", "autoblock", "allowed",
                             f"{target.username} blocked after {target.warnings} warnings")
    return {"viewer": target.username, "warnings": target.warnings, "blocked": target.is_blocked}


@router.post("/warnings/ack")
def ack(c: Caller = Depends(current_user), db: Session = Depends(get_db, scope="function")):
    u = db.get(User, c.user.id)
    u.warnings_seen = u.warnings
    c.audit("warning ack", "allowed")
    return {"warnings_seen": u.warnings_seen}


@router.post("/messages", status_code=201)
def message(body: MessageIn, c: Caller = Depends(require_roles("OWNER", "VIEWER")), db: Session = Depends(get_db, scope="function")):
    d, _ = guard(db, c, body.document_id, "read", "message", "message to owner")
    if d.owner_id == c.user.id:
        raise HTTPException(422, "You own this document.")
    limiter.check(f"dm:{c.user.id}", 5, 60)
    db.add(Message(sender_id=c.user.id, recipient_id=d.owner_id, document_id=d.id, body=body.body.strip()))
    return {"to": d.owner.username}


@router.get("/messages")
def inbox(c: Caller = Depends(require_roles("OWNER")), db: Session = Depends(get_db, scope="function")):
    rows = db.execute(select(Message).where(Message.recipient_id == c.user.id)
                      .order_by(Message.id.desc()).limit(200)).scalars()
    return [{"at": m.created_at.isoformat(timespec="seconds") + "Z", "from": m.sender.username,
             "document": f"D-{m.document_id}", "body": m.body} for m in rows]


@router.get("/shared")
def shared_with_me(c: Caller = Depends(current_user), db: Session = Depends(get_db, scope="function")):
    stmt = (select(Document).join(DocumentGrant, DocumentGrant.document_id == Document.id)
            .where(DocumentGrant.user_id == c.user.id, Document.is_deleted.is_(False)))
    out = []
    for d in db.execute(stmt).unique().scalars():
        if not d.owner.is_blocked:
            out.append({"id": d.ref, "name": d.name, "owner": d.owner.username, "has_passcode": bool(d.passcode_hash)})
    return out
