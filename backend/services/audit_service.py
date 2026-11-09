"""Append-only, hash-chained audit trail.

Entries are written on their own connection and committed immediately, so a refused
attempt is recorded even when the request that caused it is rolled back.
The chain hash itself is computed by MySQL (trigger trg_audit_logs_chain); this module
recomputes it in Python to verify the chain end to end.
"""
from __future__ import annotations

import hashlib
import logging

from sqlalchemy import insert, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from database import engine
from models import AuditLog, utcnow

log = logging.getLogger("trustvault.audit")
GENESIS = "0" * 64


def _clean(value, limit: int) -> str:
    return "".join(ch for ch in str(value or "") if ch.isprintable())[:limit]


def record(actor: str, action: str, result: str, detail: str = "", *, document_ref: str = "",
           doc_owner_id: int | None = None, ip: str = "") -> None:
    assert result in ("allowed", "denied")
    row = dict(created_at=utcnow(), actor=_clean(actor, 32) or "anonymous", action=_clean(action, 40),
               document_ref=_clean(document_ref, 16), doc_owner_id=doc_owner_id, result=result,
               detail=_clean(detail, 255), ip=_clean(ip, 45))
    # One dedicated connection holds the named lock, inserts and releases, so two writers
    # can never read the same previous hash and fork the chain.
    with engine.connect() as conn:
        if conn.execute(text("SELECT GET_LOCK('tv_audit_chain', 10)")).scalar() != 1:
            log.error("could not obtain the audit chain lock")
            raise RuntimeError("could not obtain the audit chain lock")
        try:
            conn.execute(insert(AuditLog.__table__).values(**row))
            conn.commit()
        except Exception:
            conn.rollback()
            log.exception("audit write failed")
            raise
        finally:
            conn.execute(text("SELECT RELEASE_LOCK('tv_audit_chain')"))
            conn.commit()


def expected_hash(e: AuditLog, previous: str) -> str:
    owner = "" if e.doc_owner_id is None else str(e.doc_owner_id)
    payload = "|".join([previous, e.created_at.strftime("%Y-%m-%d %H:%M:%S.%f"), e.actor, e.action,
                        e.document_ref, owner, e.result, e.detail, e.ip])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_chain(db: Session) -> dict:
    """Walk the whole chain. Returns {'ok', 'entries', 'broken_at'}."""
    previous, count = GENESIS, 0
    for e in db.execute(select(AuditLog).order_by(AuditLog.id)).scalars().yield_per(1000):
        count += 1
        if e.previous_hash != previous or expected_hash(e, previous) != e.entry_hash:
            return {"ok": False, "entries": count, "broken_at": e.id}
        previous = e.entry_hash
    return {"ok": True, "entries": count, "broken_at": None}


def tamper_probe(db: Session) -> dict:
    """Try to alter and delete the first entry. The triggers must refuse both."""
    outcomes = {}
    for label, sql in (("update", "UPDATE audit_logs SET detail = 'edited quietly' ORDER BY id LIMIT 1"),
                       ("delete", "DELETE FROM audit_logs ORDER BY id LIMIT 1")):
        try:
            with db.begin_nested():
                db.execute(text(sql))
            outcomes[label] = "NOT BLOCKED"
        except DBAPIError as exc:
            msg = str(getattr(exc.orig, "args", [None, ""])[1]) if exc.orig else str(exc)
            outcomes[label] = f"blocked: {msg}"
    return outcomes
