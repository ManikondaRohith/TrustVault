"""Administration, audit trail and statistics."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from auth import Caller, can, current_user, require_roles
from database import get_db
from models import AuditLog, Document, DocumentGrant, Report, User
from schemas import RoleIn
from security import validate_upload
from services import audit_service

router = APIRouter(prefix="/api", tags=["admin"])
admin_only = require_roles("ADMIN")


def _target(db: Session, c: Caller, username: str, action: str) -> User:
    t = db.execute(select(User).where(User.username == username[:32])).scalar_one_or_none()
    if t is None or t.role == "ADMIN" or t.id == c.user.id:
        c.audit(action, "denied", f"{username[:32]}: not allowed")
        raise HTTPException(403, "Refused.")
    return t


# ---------------------------------------------------------------------------
# People
# ---------------------------------------------------------------------------
@router.get("/admin/users")
def users(c: Caller = Depends(admin_only), db: Session = Depends(get_db, scope="function")):
    c.audit("contact audit", "allowed", "admin viewed verified contact details")
    rows = db.execute(select(User).where(User.role != "ADMIN").order_by(User.username)).scalars()
    return [{"username": u.username, "role": u.role, "email": u.email,
             "verified": u.is_verified, "blocked": u.is_blocked, "warnings": u.warnings,
             "reset_pending": u.must_reset} for u in rows]


@router.patch("/admin/users/{username}/role")
def set_role(username: str, body: RoleIn, c: Caller = Depends(admin_only), db: Session = Depends(get_db, scope="function")):
    t = _target(db, c, username, "role")
    old, t.role = t.role, body.role
    if body.role == "OWNER":   # owner-role grantees are read-only: downgrade any edit/rename grants
        for g in db.execute(select(DocumentGrant).where(DocumentGrant.user_id == t.id)).scalars():
            g.level, g.can_rename = "READ", False
    t.token_version += 1       # role change takes effect on the next request
    c.audit("role", "allowed", f"{t.username}: {old} → {t.role}")
    return {"username": t.username, "role": t.role}


@router.post("/admin/users/{username}/block")
def block(username: str, c: Caller = Depends(admin_only), db: Session = Depends(get_db, scope="function")):
    t = _target(db, c, username, "block")
    t.is_blocked = True
    t.token_version += 1       # end their sessions; their documents lock for everyone (see can())
    c.audit("block", "allowed", t.username)
    return {"username": t.username, "blocked": True}


@router.post("/admin/users/{username}/unblock")
def unblock(username: str, c: Caller = Depends(admin_only), db: Session = Depends(get_db, scope="function")):
    t = _target(db, c, username, "unblock")
    t.is_blocked, t.warnings, t.warnings_seen = False, 0, 0
    c.audit("unblock", "allowed", t.username)
    return {"username": t.username, "blocked": False}


@router.post("/admin/users/{username}/reset")
def reset(username: str, c: Caller = Depends(admin_only), db: Session = Depends(get_db, scope="function")):
    t = _target(db, c, username, "reset credentials")
    t.must_reset = True
    t.token_version += 1
    c.audit("reset credentials", "allowed", t.username)
    return {"username": t.username, "reset_pending": True}


@router.get("/admin/reports")
def reports(c: Caller = Depends(admin_only), db: Session = Depends(get_db, scope="function")):
    rows = db.execute(select(Report).order_by(Report.id.desc()).limit(500)).scalars()
    return [{"at": r.created_at.isoformat(timespec="seconds") + "Z", "from": r.reporter.username,
             "category": r.category, "about": r.target.username,
             "document": f"D-{r.document_id}" if r.document_id else "", "details": r.details} for r in rows]


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------
def _visible(c: Caller):
    stmt = select(AuditLog)
    if c.user.role != "ADMIN":
        stmt = stmt.where(or_(AuditLog.actor == c.user.username, AuditLog.doc_owner_id == c.user.id))
    return stmt


@router.get("/audit")
def audit(denied_only: bool = False, actor: str = "", action: str = "", limit: int = 500,
          c: Caller = Depends(current_user), db: Session = Depends(get_db, scope="function")):
    stmt = _visible(c)
    if denied_only:
        stmt = stmt.where(AuditLog.result == "denied")
    if actor and c.user.role == "ADMIN":
        stmt = stmt.where(AuditLog.actor == actor[:32])
    if action and c.user.role == "ADMIN":
        stmt = stmt.where(AuditLog.action == action[:40])
    rows = db.execute(stmt.order_by(AuditLog.id.desc()).limit(max(1, min(limit, 2000)))).scalars()
    out = [{"id": e.id, "at": e.created_at.isoformat(timespec="seconds") + "Z", "actor": e.actor,
            "action": e.action, "document": e.document_ref or "—", "result": e.result, "detail": e.detail,
            "hash": e.entry_hash[:12]} for e in rows]
    facets = {}
    if c.user.role == "ADMIN":
        facets = {"actors": [r[0] for r in db.execute(select(AuditLog.actor).distinct().order_by(AuditLog.actor))],
                  "actions": [r[0] for r in db.execute(select(AuditLog.action).distinct().order_by(AuditLog.action))]}
        noisy = db.execute(select(AuditLog.actor, func.count()).where(AuditLog.result == "denied")
                           .group_by(AuditLog.actor).having(func.count() >= 3)).all()
        changes = db.execute(select(func.count()).select_from(AuditLog)
                             .where(AuditLog.action.in_(("grant", "revoke")))).scalar()
        facets["worth_noticing"] = {"refused_3_plus": [{"actor": a, "count": n} for a, n in noisy],
                                    "permission_changes": changes}
    return {"entries": out, **facets}


@router.get("/audit/verify")
def verify(c: Caller = Depends(current_user), db: Session = Depends(get_db, scope="function")):
    return audit_service.verify_chain(db)


@router.post("/admin/audit/tamper-test")
def tamper_test(c: Caller = Depends(admin_only), db: Session = Depends(get_db, scope="function")):
    out = audit_service.tamper_probe(db)
    ok = all(v.startswith("blocked") for v in out.values())
    c.audit("tamper test", "allowed" if ok else "denied", "triggers refused update+delete" if ok else "TRIGGERS MISSING")
    return {"protected": ok, "results": out, "chain": audit_service.verify_chain(db)}


@router.post("/admin/selftest")
def selftest(c: Caller = Depends(admin_only)):
    """Unit checks against the same can() every route uses (in-memory objects, no DB writes)."""
    def U(i, role="VIEWER", blocked=False):
        return User(id=i, username=f"u{i}", role=role, is_blocked=blocked)

    def D(owner, blocked_owner=False, deleted=False):
        d = Document(id=1, owner_id=owner.id, is_deleted=deleted)
        d.owner = U(owner.id, owner.role, blocked_owner)
        return d

    def G(level="READ", rn=False):
        return DocumentGrant(level=level, can_rename=rn)

    o, v, a, co = U(1, "OWNER"), U(2), U(3, "ADMIN"), U(4, "OWNER")
    T = [
        ("a stranger cannot read", not can(v, D(o), "read", None)),
        ("a read grant cannot edit", can(v, D(o), "read", G()) and not can(v, D(o), "edit", G())),
        ("an edit grant implies read", can(v, D(o), "read", G("EDIT"))),
        ("a grantee cannot share or delete", not can(v, D(o), "own", G("EDIT"))),
        ("an admin can read vault documents without a grant", can(a, D(o), "read", None)),
        ("an admin cannot edit vault documents", not can(a, D(o), "edit", G("EDIT"))),
        ("an admin cannot share or delete vault documents", not can(a, D(o), "own", G("EDIT"))),
        ("a deleted document is unreachable, even for its owner", not can(o, D(o, deleted=True), "read", None)),
        ("a blocked owner locks the document for grantees", not can(v, D(o, blocked_owner=True), "read", G())),
        ("rename needs its own flag", not can(v, D(o), "rename", G("EDIT")) and can(v, D(o), "rename", G("EDIT", True))),
        ("an owner with an edit grant stays read-only", not can(co, D(o), "edit", G("EDIT")) and can(co, D(o), "read", G("EDIT"))),
        ("a blocked user is refused", not can(U(2, blocked=True), D(o), "read", G())),
        ("a fake PDF (program bytes) is rejected", validate_upload("invoice.pdf", b"MZ\x01\x02") is not None),
        ("a double extension is rejected", validate_upload("a.php.txt", b"hi") is not None),
        ("an SVG with script is rejected", validate_upload("x.svg", b"<svg><script>1</script></svg>") is not None),
    ]
    return {"passed": sum(ok for _, ok in T), "total": len(T), "tests": [{"name": n, "ok": ok} for n, ok in T]}


# ---------------------------------------------------------------------------
# Overview numbers
# ---------------------------------------------------------------------------
@router.get("/stats")
def stats(c: Caller = Depends(current_user), db: Session = Depends(get_db, scope="function")):
    docs = select(func.count()).select_from(Document).where(Document.is_deleted.is_(False))
    if c.user.role != "ADMIN":
        granted = select(DocumentGrant.document_id).where(DocumentGrant.user_id == c.user.id)
        docs = docs.where(or_(Document.owner_id == c.user.id, Document.id.in_(granted)))
    vis = _visible(c).subquery()
    return {
        "documents": db.execute(docs).scalar(),
        "refused": db.execute(select(func.count()).select_from(vis).where(vis.c.result == "denied")).scalar(),
        "audit_entries": db.execute(select(func.count()).select_from(vis)).scalar(),
    }
