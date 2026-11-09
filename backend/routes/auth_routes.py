"""Sign-up (email code), sign-in (password only), forgot password (email code), sign-out, password change."""
from __future__ import annotations

import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from auth import Caller, current_user_allow_reset
from config import settings
from database import get_db
from models import OtpCode, PendingSignup, User, utcnow
from schemas import (ChallengeOnly, ForgotReset, ForgotStart, ForgotVerify, Login, MeOut, PasswordChange,
                     SignupStart, SignupVerify)
from security import (EMAIL_RE, USERNAME_RE, client_ip, clear_session_cookie, hash_password, issue_token,
                      limiter, lock_clear, lock_fail, lock_remaining, mask_email, password_problem,
                      set_session_cookie, verify_password)
from services import audit_service, otp_service

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _me(u: User) -> MeOut:
    return MeOut(username=u.username, display_name=u.display_name, role=u.role, is_verified=u.is_verified,
                 must_reset=u.must_reset, warnings=u.warnings, warnings_seen=u.warnings_seen)


def _start_session(response: Response, user: User) -> None:
    set_session_cookie(response, issue_token(user.id, user.token_version))


def _deliver(fn):
    try:
        fn()
    except otp_service.DeliveryError:
        raise HTTPException(503, "We could not send the verification code. Please try again later.")


# ---------------------------------------------------------------------------
# Sign-up: details -> one emailed code -> VIEWER account
# ---------------------------------------------------------------------------
@router.post("/signup/start")
def signup_start(body: SignupStart, request: Request, db: Session = Depends(get_db, scope="function")):
    ip = client_ip(request)
    limiter.check(f"signup:{ip}", settings.rate_signup_per_10min, 600)
    username, email = body.username.strip(), body.email.strip().lower()
    if not USERNAME_RE.match(username):
        raise HTTPException(422, "Username: 3–32 letters, digits or underscores, starting with a letter.")
    problem = password_problem(body.password, username)
    if problem:
        raise HTTPException(422, problem)
    if not EMAIL_RE.match(email):
        raise HTTPException(422, "Enter a valid email address.")
    if db.execute(select(User.id).where(User.username == username)).first():
        raise HTTPException(409, "That username is taken.")
    if db.execute(select(User.id).where(User.email == email)).first():
        raise HTTPException(409, "That email is already registered.")

    db.execute(delete(PendingSignup).where(PendingSignup.expires_at < utcnow()))
    otp_service.purge_expired(db)
    pending = PendingSignup(id=str(uuid.uuid4()), username=username, email=email,
                            password_hash=hash_password(body.password),
                            expires_at=utcnow() + timedelta(minutes=30))
    db.add(pending)
    db.flush()
    _deliver(lambda: otp_service.issue(db, challenge_id=pending.id, purpose="SIGNUP", destination=email))
    audit_service.record(username, "verify", "allowed", "sign-up code issued", ip=ip)
    return {"challenge_id": pending.id, "email": mask_email(email), "expires_in": settings.otp_ttl_seconds}


@router.post("/signup/resend")
def signup_resend(body: ChallengeOnly, request: Request, db: Session = Depends(get_db, scope="function")):
    ip = client_ip(request)
    limiter.check(f"resend:{body.challenge_id}", 3, 600)
    limiter.check(f"signup:{ip}", settings.rate_signup_per_10min, 600)
    p = db.get(PendingSignup, body.challenge_id)
    if p is None or p.expires_at < utcnow():
        raise HTTPException(410, "This sign-up has expired. Please start again.")
    _deliver(lambda: otp_service.issue(db, challenge_id=p.id, purpose="SIGNUP", destination=p.email))
    audit_service.record(p.username, "verify", "allowed", "sign-up code re-issued", ip=ip)
    return {"expires_in": settings.otp_ttl_seconds}


@router.post("/signup/verify", response_model=MeOut)
def signup_verify(body: SignupVerify, request: Request, response: Response, db: Session = Depends(get_db, scope="function")):
    ip = client_ip(request)
    limiter.check(f"verify:{ip}", 30, 600)
    p = db.get(PendingSignup, body.challenge_id, with_for_update=True)
    if p is None or p.expires_at < utcnow():
        raise HTTPException(410, "This sign-up has expired. Please start again.")
    result = otp_service.verify(db, challenge_id=p.id, purpose="SIGNUP", code=body.code.strip())
    if result != "ok":
        db.commit()  # keep the attempt counter even though we refuse
        audit_service.record(p.username, "verify", "denied", "bad or expired sign-up code", ip=ip)
        if result == "expired":
            raise HTTPException(410, "Code expired or too many attempts. Press Resend code.")
        raise HTTPException(400, "That code is wrong.")
    if db.execute(select(User.id).where((User.username == p.username) | (User.email == p.email))).first():
        raise HTTPException(409, "That username or email was registered meanwhile.")
    user = User(username=p.username, display_name=p.username, role="VIEWER", email=p.email,
                password_hash=p.password_hash, is_verified=True)
    db.add(user)
    db.delete(p)
    db.flush()
    audit_service.record(user.username, "signup", "allowed", "role VIEWER; email verified", ip=ip)
    _start_session(response, user)
    return _me(user)


# ---------------------------------------------------------------------------
# Sign-in: username + password only (no one-time code)
# ---------------------------------------------------------------------------
@router.post("/login")
def login(body: Login, request: Request, response: Response, db: Session = Depends(get_db, scope="function")):
    ip = client_ip(request)
    limiter.check(f"login:{ip}", settings.rate_login_per_min, 60)
    name = body.username.strip()
    wait = lock_remaining(db, "login", name, ip)
    if wait:
        raise HTTPException(429, f"Locked for {max(1, wait // 60)} min after repeated failures.")
    user = db.execute(select(User).where(User.username == name)).scalar_one_or_none()
    if not verify_password(body.password, user.password_hash if user else None):
        lock_fail(db, "login", name, ip)
        db.commit()
        audit_service.record(name[:32], "login", "denied", "bad credentials", ip=ip)
        raise HTTPException(401, "Wrong username or password.")
    if user.is_blocked:
        audit_service.record(user.username, "login", "denied", "blocked account", ip=ip)
        raise HTTPException(403, "This account is blocked. Contact an administrator.")
    lock_clear(db, "login", name, ip)
    audit_service.record(user.username, "login", "allowed", "", ip=ip)
    _start_session(response, user)
    return {"user": _me(user)}


# ---------------------------------------------------------------------------
# Forgot password: email -> emailed code -> check code -> new password
# ---------------------------------------------------------------------------
@router.post("/forgot/start")
def forgot_start(body: ForgotStart, request: Request, db: Session = Depends(get_db, scope="function")):
    ip = client_ip(request)
    limiter.check(f"forgot:{ip}", settings.rate_signup_per_10min, 600)
    email = body.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(422, "Enter a valid email address.")
    limiter.check(f"forgot-email:{email}", 3, 600)
    challenge = str(uuid.uuid4())
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    # The answer is identical whether or not the address is registered, so it cannot be used to
    # find out who has an account. A code is only really sent to a registered, unblocked account.
    if user is not None and not user.is_blocked:
        otp_service.purge_expired(db)
        _deliver(lambda: otp_service.issue(db, challenge_id=challenge, purpose="RESET", destination=email,
                                           user_id=user.id))
        audit_service.record(user.username, "password reset", "allowed", "reset code issued", ip=ip)
    return {"challenge_id": challenge, "email": mask_email(email), "expires_in": settings.otp_ttl_seconds}


def _check_reset_code(db: Session, body, ip: str, consume: bool) -> OtpCode:
    row = db.execute(select(OtpCode).where(OtpCode.challenge_id == body.challenge_id, OtpCode.purpose == "RESET",
                                           OtpCode.is_used.is_(False)).order_by(OtpCode.id.desc()).limit(1)
                     ).scalar_one_or_none()
    user = db.get(User, row.user_id) if row is not None and row.user_id else None
    if row is None or user is None:
        raise HTTPException(410, "This reset has expired. Please start again.")
    result = otp_service.verify(db, challenge_id=body.challenge_id, purpose="RESET", code=body.code.strip(),
                                consume=consume)
    if result != "ok":
        db.commit()  # keep the attempt counter even though we refuse
        audit_service.record(user.username, "password reset", "denied", f"{result} reset code", ip=ip)
        if result == "expired":
            raise HTTPException(410, "Code expired or too many attempts. Please start again.")
        raise HTTPException(400, "That code is wrong.")
    return row


@router.post("/forgot/verify")
def forgot_verify(body: ForgotVerify, request: Request, db: Session = Depends(get_db, scope="function")):
    """Check the emailed code without using it up; the final reset call consumes it."""
    ip = client_ip(request)
    limiter.check(f"verify:{ip}", 30, 600)
    _check_reset_code(db, body, ip, consume=False)
    return {"ok": True}


@router.post("/forgot/reset")
def forgot_reset(body: ForgotReset, request: Request, db: Session = Depends(get_db, scope="function")):
    ip = client_ip(request)
    limiter.check(f"verify:{ip}", 30, 600)
    row = db.execute(select(OtpCode).where(OtpCode.challenge_id == body.challenge_id, OtpCode.purpose == "RESET",
                                           OtpCode.is_used.is_(False)).order_by(OtpCode.id.desc()).limit(1)
                     ).scalar_one_or_none()
    user = db.get(User, row.user_id) if row is not None and row.user_id else None
    if user is None:
        raise HTTPException(410, "This reset has expired. Please start again.")
    # Password checks come first so a typo in the new password does not burn the code.
    problem = password_problem(body.new_password, user.username)
    if problem:
        raise HTTPException(422, problem)
    if verify_password(body.new_password, user.password_hash):
        raise HTTPException(422, "Choose a password you have not used here before.")
    _check_reset_code(db, body, ip, consume=True)
    if user.is_blocked:
        raise HTTPException(403, "This account is blocked. Contact an administrator.")
    user.password_hash = hash_password(body.new_password)
    user.must_reset = False
    user.token_version += 1            # every session issued so far stops working
    db.execute(update(OtpCode).where(OtpCode.user_id == user.id, OtpCode.purpose == "RESET",
                                     OtpCode.is_used.is_(False)).values(is_used=True))
    lock_clear(db, "login", user.username, ip)
    db.flush()
    audit_service.record(user.username, "password reset", "allowed", "password reset by email code", ip=ip)
    return {"ok": True}


@router.post("/logout")
def logout(response: Response, c: Caller = Depends(current_user_allow_reset), db: Session = Depends(get_db, scope="function")):
    user = db.get(User, c.user.id)
    user.token_version += 1          # every token issued so far stops working
    c.audit("logout", "allowed")
    clear_session_cookie(response)
    return {"ok": True}


@router.get("/me", response_model=MeOut)
def me(c: Caller = Depends(current_user_allow_reset)):
    return _me(c.user)


@router.post("/password", response_model=MeOut)
def change_password(body: PasswordChange, response: Response, c: Caller = Depends(current_user_allow_reset),
                    db: Session = Depends(get_db, scope="function")):
    limiter.check(f"pw:{c.user.id}", 10, 600)
    user = db.get(User, c.user.id)
    if not verify_password(body.current_password, user.password_hash):
        c.audit("credentials", "denied", "wrong current password")
        raise HTTPException(400, "Your current password is wrong.")
    problem = password_problem(body.new_password, user.username)
    if problem:
        raise HTTPException(422, problem)
    if verify_password(body.new_password, user.password_hash):
        raise HTTPException(422, "Choose a password you have not used here before.")
    user.password_hash = hash_password(body.new_password)
    user.must_reset = False
    user.token_version += 1
    db.flush()
    c.audit("credentials", "allowed", "password changed")
    _start_session(response, user)
    return _me(user)
