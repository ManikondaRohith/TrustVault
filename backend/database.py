"""PostgreSQL engine, additive schema bootstrap and session factory."""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from config import settings


class Base(DeclarativeBase):
    pass


engine = create_engine(
    settings.database_url or "postgresql+psycopg://invalid:invalid@localhost/invalid",
    pool_pre_ping=True,
    pool_recycle=1800,
    pool_size=5,
    max_overflow=5,
    connect_args={"connect_timeout": 15},
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, class_=Session)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


REQUIRED_TABLES = {
    "users", "documents", "document_blobs", "document_grants", "pending_signups",
    "otp_codes", "lockouts", "reports", "messages", "audit_logs",
}


def check_schema() -> None:
    """Create missing PostgreSQL tables and install immutable audit triggers.

    This operation is additive. It never drops or truncates existing data.
    """
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        # Render Postgres provides pgcrypto. If extension creation is disallowed,
        # startup fails clearly instead of running without audit integrity.
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))
        conn.execute(text("""
            CREATE OR REPLACE FUNCTION trustvault_audit_chain_insert()
            RETURNS trigger LANGUAGE plpgsql AS $$
            DECLARE
                prev CHAR(64);
                payload TEXT;
            BEGIN
                PERFORM pg_advisory_xact_lock(7412026, 1);
                SELECT entry_hash INTO prev FROM audit_logs ORDER BY id DESC LIMIT 1;
                NEW.previous_hash := COALESCE(prev, repeat('0', 64));
                payload := concat_ws('|',
                    NEW.previous_hash,
                    to_char(NEW.created_at, 'YYYY-MM-DD HH24:MI:SS.US'),
                    NEW.actor, NEW.action, NEW.document_ref,
                    COALESCE(NEW.doc_owner_id::text, ''), NEW.result::text,
                    NEW.detail, NEW.ip
                );
                NEW.entry_hash := encode(digest(payload, 'sha256'), 'hex');
                RETURN NEW;
            END;
            $$;
        """))
        conn.execute(text("""
            CREATE OR REPLACE FUNCTION trustvault_audit_no_mutation()
            RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'audit_logs is append-only: % is forbidden', TG_OP;
            END;
            $$;
        """))
        conn.execute(text("DROP TRIGGER IF EXISTS trg_audit_logs_chain ON audit_logs"))
        conn.execute(text("DROP TRIGGER IF EXISTS trg_audit_logs_no_update ON audit_logs"))
        conn.execute(text("DROP TRIGGER IF EXISTS trg_audit_logs_no_delete ON audit_logs"))
        conn.execute(text("""
            CREATE TRIGGER trg_audit_logs_chain BEFORE INSERT ON audit_logs
            FOR EACH ROW EXECUTE FUNCTION trustvault_audit_chain_insert()
        """))
        conn.execute(text("""
            CREATE TRIGGER trg_audit_logs_no_update BEFORE UPDATE ON audit_logs
            FOR EACH ROW EXECUTE FUNCTION trustvault_audit_no_mutation()
        """))
        conn.execute(text("""
            CREATE TRIGGER trg_audit_logs_no_delete BEFORE DELETE ON audit_logs
            FOR EACH ROW EXECUTE FUNCTION trustvault_audit_no_mutation()
        """))
        tables = set(conn.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname = current_schema()"
        )).scalars())
        missing = REQUIRED_TABLES - tables
        if missing:
            raise RuntimeError(f"PostgreSQL schema incomplete; missing tables: {sorted(missing)}")
