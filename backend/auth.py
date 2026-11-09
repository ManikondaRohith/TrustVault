"""Authentication dependencies and the single access-decision function `can()`.

Every route resolves the caller through `current_user` (cookie -> JWT -> live DB row) and
every document decision goes through `can()`. Nothing the browser sends about roles or
permissions is trusted.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from database import get_db
from models import Document, DocumentGrant, User
from security import COOKIE_NAME, client_ip, decode_token, issue_token, set_session_cookie
from services import audit_service


@dataclass
class Caller:
    user: User
    ip: str

    def audit(self, action: str, result: str, detail: str = "", doc: Document | None = None,
              document_ref: str = "") -> None:
        audit_service.record(
            self.user.username, action, result, detail, ip=self.ip,
            document_ref=doc.ref if doc is not None else document_ref,
            doc_owner_id=doc.owner_id if doc is not None else None,
        )


def _resolve(request: Request, response: Response, db: Session, allow_reset: bool) -> Caller:
    token = request.cookies.get(COOKIE_NAME)
    claims = decode_token(token) if token else None
    if not claims:
        raise HTTPException(401, "Sign in required.")
    user = db.get(User, int(claims["sub"]))
    if user is None or claims.get("ver") != user.token_version:
        raise HTTPException(401, "Session ended. Please sign in again.")
    if user.is_blocked:
        raise HTTPException(403, "This account is blocked. Contact an administrator.")
    if user.must_reset and not allow_reset:
        raise HTTPException(403, "Password change required.")
    # Sliding 15-minute idle session: re-issue after 2 minutes of use.
    age = datetime.now(timezone.utc).timestamp() - claims["iat"]
    if age > 120:
        set_session_cookie(response, issue_token(user.id, user.token_version))
    return Caller(user=user, ip=client_ip(request))


def current_user(request: Request, response: Response, db: Session = Depends(get_db, scope="function")) -> Caller:
    return _resolve(request, response, db, allow_reset=False)


def current_user_allow_reset(request: Request, response: Response, db: Session = Depends(get_db, scope="function")) -> Caller:
    return _resolve(request, response, db, allow_reset=True)


def require_roles(*roles: str):
    def dep(c: Caller = Depends(current_user)) -> Caller:
        if c.user.role not in roles:
            c.audit("role check", "denied", f"needs {'/'.join(roles)}; has {c.user.role}")
            raise HTTPException(403, "Your role does not allow this.")
        return c
    return dep


# ---------------------------------------------------------------------------
# The one place that decides document access
# ---------------------------------------------------------------------------
def grant_for(db: Session, doc: Document, user: User) -> DocumentGrant | None:
    return db.execute(select(DocumentGrant).where(DocumentGrant.document_id == doc.id,
                                                  DocumentGrant.user_id == user.id)).scalar_one_or_none()


def can(user: User | None, doc: Document | None, perm: str, grant: DocumentGrant | None) -> bool:
    """perm: read | edit | rename | own.

    * blocked users, deleted documents and documents of blocked owners: nobody
    * the owner: everything
    * 'own' (share, revoke, passcode, delete): owner only
    * others need a live grant; OWNER-role grantees are always read-only;
      'edit' needs an EDIT grant, 'rename' needs its own flag
    * ADMIN users never hold grants, so they can never read content
    """
    if user is None or doc is None or user.is_blocked or doc.is_deleted or doc.owner.is_blocked:
        return False
    if doc.owner_id == user.id:
        return True
    if perm == "own" or grant is None or user.role == "ADMIN":
        return False
    if perm == "read":
        return True
    if user.role == "OWNER":
        return False
    if perm == "rename":
        return bool(grant.can_rename)
    if perm == "edit":
        return grant.level == "EDIT"
    return False


def parse_ref(ref: str) -> int | None:
    ref = (ref or "").strip().upper()
    if ref.startswith("D-") and ref[2:].isdigit() and len(ref) <= 12:
        return int(ref[2:])
    return None


def load_doc(db: Session, ref: str) -> Document | None:
    did = parse_ref(ref)
    return db.get(Document, did) if did is not None else None


def guard(db: Session, c: Caller, ref: str, perm: str, action: str, detail: str = "") -> tuple[Document, DocumentGrant | None]:
    """Load a document and enforce `perm`; record the outcome either way."""
    doc = load_doc(db, ref)
    grant = grant_for(db, doc, c.user) if doc is not None else None
    if not can(c.user, doc, perm, grant):
        safe_ref = doc.ref if doc else "".join(ch for ch in (ref or "") if ch.isalnum() or ch == "-")[:16]
        c.audit(action, "denied", detail or f"needs {perm}", doc=doc, document_ref=safe_ref)
        related = doc is not None and (doc.owner_id == c.user.id or grant is not None)
        if related and not doc.is_deleted and doc.owner.is_blocked:
            raise HTTPException(423, "This document's owner is blocked by an administrator.")
        # Same answer whether the document is missing or forbidden: no ID enumeration.
        raise HTTPException(403, "Refused. This attempt has been recorded.")
    c.audit(action, "allowed", detail, doc=doc)
    return doc, grant
