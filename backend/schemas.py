"""Pydantic request/response models. Unknown fields are rejected (extra='forbid')."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


# ---- auth -------------------------------------------------------------------
class SignupStart(Strict):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=128)
    email: str = Field(min_length=3, max_length=254)


class SignupVerify(Strict):
    challenge_id: str = Field(min_length=36, max_length=36)
    code: str = Field(min_length=1, max_length=6)


class ChallengeOnly(Strict):
    challenge_id: str = Field(min_length=36, max_length=36)


class Login(Strict):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=128)


class ForgotStart(Strict):
    email: str = Field(min_length=3, max_length=254)


class ForgotVerify(Strict):
    challenge_id: str = Field(min_length=36, max_length=36)
    code: str = Field(min_length=1, max_length=6)


class ForgotReset(Strict):
    challenge_id: str = Field(min_length=36, max_length=36)
    code: str = Field(min_length=1, max_length=6)
    new_password: str = Field(min_length=1, max_length=128)


class PasswordChange(Strict):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=128)


class MeOut(BaseModel):
    username: str
    display_name: str
    role: str
    is_verified: bool
    must_reset: bool
    warnings: int
    warnings_seen: int


# ---- documents --------------------------------------------------------------
Category = Literal["HR", "Contracts", "Drawings", "Audit", "Other"]


class TextPage(Strict):
    name: str = Field(min_length=1, max_length=60)
    category: Category = "Other"
    text: str = Field(min_length=1, max_length=20000)


class Unlock(Strict):
    passcode: str | None = Field(default=None, max_length=128)


class TextEdit(Strict):
    text: str = Field(max_length=20000)
    passcode: str | None = Field(default=None, max_length=128)


class Rename(Strict):
    name: str = Field(min_length=1, max_length=80)
    passcode: str | None = Field(default=None, max_length=128)


class GrantIn(Strict):
    level: Literal["read", "edit"] = "read"
    can_rename: bool = False


class PasscodeIn(Strict):
    passcode: str = Field(min_length=8, max_length=128)


class Probe(Strict):
    document_id: str = Field(min_length=1, max_length=24)


# ---- safety -----------------------------------------------------------------
ReportCategory = Literal["Harassment", "Inappropriate content", "Data misuse", "Other misconduct"]


class ReportIn(Strict):
    category: ReportCategory
    viewer: str = Field(min_length=3, max_length=32)
    details: str = Field(min_length=10, max_length=500)
    document_id: str | None = Field(default=None, max_length=16)


class MessageIn(Strict):
    document_id: str = Field(min_length=3, max_length=16)
    body: str = Field(min_length=5, max_length=500)


# ---- admin ------------------------------------------------------------------
class RoleIn(Strict):
    role: Literal["OWNER", "VIEWER"]
