"""Append-only, hash-chained audit trail for PostgreSQL."""
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
    # The trigger takes the same transaction-scoped lock before selecting the
    # previous hash and inserting, so concurrent writers cannot fork the chain.
    with engine.begin() as conn:
        conn.execute(insert(AuditLog.__table__).values(**row))


def expected_hash(e: AuditLog, previous: str) -> str:
    owner = "" if e.doc_owner_id is None else str(e.doc_owner_id)
    payload = "|".join([previous, e.created_at.strftime("%Y-%m-%d %H:%M:%S.%f"), e.actor, e.action,
                        e.document_ref, owner, e.result, e.detail, e.ip])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_chain(db: Session) -> dict:
    previous, count = GENESIS, 0
    for e in db.execute(select(AuditLog).order_by(AuditLog.id)).scalars().yield_per(1000):
        count += 1
        if e.previous_hash != previous or expected_hash(e, previous) != e.entry_hash:
            return {"ok": False, "entries": count, "broken_at": e.id}
        previous = e.entry_hash
    return {"ok": True, "entries": count, "broken_at": None}


def tamper_probe(db: Session) -> dict:
    outcomes = {}
    statements = (
        ("update", "UPDATE audit_logs SET detail = 'edited quietly' WHERE id = (SELECT id FROM audit_logs ORDER BY id LIMIT 1)"),
        ("delete", "DELETE FROM audit_logs WHERE id = (SELECT id FROM audit_logs ORDER BY id LIMIT 1)"),
    )
    for label, sql in statements:
        try:
            with db.begin_nested():
                db.execute(text(sql))
            outcomes[label] = "NOT BLOCKED"
        except DBAPIError as exc:
            outcomes[label] = f"blocked: {str(exc.orig or exc)[:180]}"
    return outcomes
