"""SQLAlchemy ORM models for PostgreSQL."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import BigInteger, Boolean, DateTime, Enum, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base

DT6 = DateTime(timezone=False)
ROLES = ("ADMIN", "OWNER", "VIEWER")
CATEGORIES = ("HR", "Contracts", "Drawings", "Audit", "Other")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True)
    display_name: Mapped[str] = mapped_column(String(80))
    role: Mapped[str] = mapped_column(Enum(*ROLES, name="role"), default="VIEWER")
    email: Mapped[str | None] = mapped_column(String(254), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    must_reset: Mapped[bool] = mapped_column(Boolean, default=False)
    warnings: Mapped[int] = mapped_column(Integer, default=0)
    warnings_seen: Mapped[int] = mapped_column(Integer, default=0)
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DT6, default=utcnow)


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(120))
    category: Mapped[str] = mapped_column(Enum(*CATEGORIES, name="category"), default="Other")
    mime_type: Mapped[str] = mapped_column(String(80))
    is_text: Mapped[bool] = mapped_column(Boolean, default=False)
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    passcode_hash: Mapped[str | None] = mapped_column(String(255))
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DT6, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DT6, default=utcnow, onupdate=utcnow)
    owner: Mapped[User] = relationship(lazy="joined")
    grants: Mapped[list["DocumentGrant"]] = relationship(back_populates="document", lazy="selectin",
                                                         cascade="all, delete-orphan")

    @property
    def ref(self) -> str:
        return f"D-{self.id}"


class DocumentBlob(Base):
    __tablename__ = "document_blobs"
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True)
    content: Mapped[bytes] = mapped_column(LargeBinary)


class DocumentGrant(Base):
    __tablename__ = "document_grants"
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    level: Mapped[str] = mapped_column(Enum("READ", "EDIT", name="level"), default="READ")
    can_rename: Mapped[bool] = mapped_column(Boolean, default=False)
    granted_at: Mapped[datetime] = mapped_column(DT6, default=utcnow)
    document: Mapped[Document] = relationship(back_populates="grants")
    user: Mapped[User] = relationship(lazy="joined")


class PendingSignup(Base):
    __tablename__ = "pending_signups"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    username: Mapped[str] = mapped_column(String(32))
    email: Mapped[str] = mapped_column(String(254))
    password_hash: Mapped[str] = mapped_column(String(255))
    expires_at: Mapped[datetime] = mapped_column(DT6)
    created_at: Mapped[datetime] = mapped_column(DT6, default=utcnow)


class OtpCode(Base):
    __tablename__ = "otp_codes"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    challenge_id: Mapped[str] = mapped_column(String(36), index=True)
    purpose: Mapped[str] = mapped_column(Enum("SIGNUP", "RESET", name="purpose"))
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    code_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DT6)
    is_used: Mapped[bool] = mapped_column(Boolean, default=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DT6, default=utcnow)


class Lockout(Base):
    __tablename__ = "lockouts"
    key_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DT6)
    updated_at: Mapped[datetime] = mapped_column(DT6, default=utcnow, onupdate=utcnow)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    reporter_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    target_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    document_id: Mapped[int | None] = mapped_column(Integer)
    category: Mapped[str] = mapped_column(String(40))
    details: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DT6, default=utcnow)
    reporter: Mapped[User] = relationship(foreign_keys=[reporter_id], lazy="joined")
    target: Mapped[User] = relationship(foreign_keys=[target_id], lazy="joined")


class Message(Base):
    __tablename__ = "messages"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    document_id: Mapped[int] = mapped_column(Integer)
    body: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DT6, default=utcnow)
    sender: Mapped[User] = relationship(foreign_keys=[sender_id], lazy="joined")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DT6)
    actor: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(40))
    document_ref: Mapped[str] = mapped_column(String(16), default="")
    doc_owner_id: Mapped[int | None] = mapped_column(Integer)
    result: Mapped[str] = mapped_column(Enum("allowed", "denied", name="result"))
    detail: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(45), default="")
    previous_hash: Mapped[str] = mapped_column(String(64), default="")
    entry_hash: Mapped[str] = mapped_column(String(64), default="")
