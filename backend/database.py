"""SQLAlchemy engine and session factory for MySQL 8 (PyMySQL driver)."""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from config import settings


class Base(DeclarativeBase):
    pass


engine = create_engine(
    settings.database_url or "mysql+pymysql://invalid/invalid",
    pool_pre_ping=True,
    pool_recycle=1800,
    pool_size=10,
    max_overflow=10,
    connect_args={"charset": "utf8mb4", "init_command": "SET time_zone = '+00:00'"},
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
REQUIRED_TRIGGERS = {"trg_audit_logs_chain", "trg_audit_logs_no_update", "trg_audit_logs_no_delete"}


def check_schema() -> None:
    """Fail fast if mysql_schema.sql has not been applied."""
    with engine.connect() as c:
        tables = {r[0] for r in c.execute(text(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()"))}
        triggers = {r[0] for r in c.execute(text(
            "SELECT trigger_name FROM information_schema.triggers WHERE trigger_schema = DATABASE()"))}
    missing = REQUIRED_TABLES - tables
    # information_schema only lists triggers to accounts holding the TRIGGER privilege. The
    # least-privilege app account (mysql_privileges.sql) does not, so an empty list is expected
    # there; a partial list means the schema really is incomplete.
    if triggers:
        missing |= REQUIRED_TRIGGERS - triggers
    if missing:
        raise RuntimeError(f"Database schema incomplete, missing: {sorted(missing)}. Apply backend/mysql_schema.sql.")
    with engine.connect() as c:
        cols = {(r[0], r[1]) for r in c.execute(text(
            "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = DATABASE()"))}
        purpose = c.execute(text(
            "SELECT column_type FROM information_schema.columns WHERE table_schema = DATABASE() "
            "AND table_name = 'otp_codes' AND column_name = 'purpose'")).scalar() or ""
    if ("otp_codes", "channel") in cols or ("pending_signups", "phone") in cols or "RESET" not in str(purpose).upper():
        raise RuntimeError(
            "This database was created by an older TrustVault (phone/SMS version). Either start from a fresh "
            "database (docker compose down -v, then start.ps1) or apply backend/migrations/001_email_only.sql "
            "as the MySQL root user. See README.md.")
