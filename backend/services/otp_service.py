"""One-time email codes: generation, hashed storage, single-use verification and delivery.

Codes never leave the server except through the configured email provider.
Delivery providers:
  smtp     (smtplib + STARTTLS, e.g. Gmail with an app password)
  sendgrid (v3 Mail Send API)
  twilio   (Twilio Email API over HTTPS)
  outbox   development only, appends to OTP_OUTBOX_PATH on the server. Refused in production.

Purposes: SIGNUP (verify the e-mail address of a new account) and RESET (forgot password).
"""
from __future__ import annotations

import base64
import html
import json
import logging
import os
import secrets
import smtplib
import ssl
import urllib.error
import urllib.request
from datetime import timedelta
from email.message import EmailMessage
from email.utils import formataddr, parseaddr

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from config import settings
from models import OtpCode, utcnow
from security import EMAIL_RE, hmac_hex

log = logging.getLogger("trustvault.otp")

# Codes are never returned to the browser. This flag exists so reviewers can grep for it.
EXPOSE_DEMO_OTPS = False
assert EXPOSE_DEMO_OTPS is False

SUBJECTS = {
    "SIGNUP": "Your TrustVault verification code",
    "RESET": "Your TrustVault password reset code",
}
BODIES = {
    "SIGNUP": "Your TrustVault verification code is {code}. It expires in 5 minutes. Never share it.",
    "RESET": ("Your TrustVault password reset code is {code}. It expires in 5 minutes. "
              "If you did not ask to reset your password, ignore this email. Never share this code."),
}


class DeliveryError(RuntimeError):
    pass


def _code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _hash(challenge_id: str, purpose: str, code: str) -> str:
    return hmac_hex(settings.otp_pepper, f"{challenge_id}:{purpose}:{code}")


# ---------------------------------------------------------------------------
# Issue / verify
# ---------------------------------------------------------------------------
def issue(db: Session, *, challenge_id: str, purpose: str, destination: str, user_id: int | None = None) -> None:
    """Invalidate earlier codes for this challenge, store a new hash, e-mail the code."""
    db.execute(update(OtpCode).where(OtpCode.challenge_id == challenge_id, OtpCode.purpose == purpose,
                                     OtpCode.is_used.is_(False)).values(is_used=True))
    code = _code()
    db.add(OtpCode(challenge_id=challenge_id, purpose=purpose, user_id=user_id,
                   code_hash=_hash(challenge_id, purpose, code),
                   expires_at=utcnow() + timedelta(seconds=settings.otp_ttl_seconds)))
    db.flush()
    send_email(destination, SUBJECTS[purpose], BODIES[purpose].format(code=code))


def verify(db: Session, *, challenge_id: str, purpose: str, code: str, consume: bool = True) -> str:
    """Return 'ok', 'wrong', or 'expired'.

    A correct code is consumed (single use) unless consume=False, which only checks it
    (used by the forgot-password flow so the code can be checked before the new password
    is typed; the final reset call consumes it). Wrong guesses always count as attempts.
    """
    row = db.execute(
        select(OtpCode).where(OtpCode.challenge_id == challenge_id, OtpCode.purpose == purpose,
                              OtpCode.is_used.is_(False))
        .order_by(OtpCode.id.desc()).limit(1).with_for_update()
    ).scalar_one_or_none()
    if row is None or row.expires_at < utcnow() or row.attempts >= settings.otp_max_attempts:
        return "expired"
    if not (isinstance(code, str) and len(code) == 6 and code.isdigit()):
        row.attempts += 1
        return "wrong"
    if not secrets.compare_digest(row.code_hash, _hash(challenge_id, purpose, code)):
        row.attempts += 1
        if row.attempts >= settings.otp_max_attempts:
            row.is_used = True
        return "wrong"
    if consume:
        row.is_used = True
    return "ok"


def purge_expired(db: Session) -> None:
    from sqlalchemy import delete
    db.execute(delete(OtpCode).where(OtpCode.expires_at < utcnow() - timedelta(days=1)))


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------
def _outbox(kind: str, to: str, body: str) -> None:
    if settings.is_production:
        raise DeliveryError("outbox delivery is disabled in production")
    os.makedirs(os.path.dirname(settings.otp_outbox_path) or ".", exist_ok=True)
    fd = os.open(settings.otp_outbox_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps({"at": utcnow().isoformat(), "kind": kind, "to": to, "body": body}) + "\n")


def _http_post(url: str, *, data: bytes, headers: dict) -> None:
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as resp:
            if resp.status >= 300:
                raise DeliveryError(f"provider returned HTTP {resp.status}")
    except urllib.error.URLError as exc:
        raise DeliveryError(f"provider request failed: {exc}") from exc


def _sender() -> tuple[str, str]:
    """Return (From header, envelope sender) from MAIL_FROM.

    MAIL_FROM may be "name <user@host>" or a bare address. A malformed value (for example two
    '@' signs) would make Gmail refuse the message, so it falls back to SMTP_USER instead of failing.
    """
    name, addr = parseaddr(settings.mail_from or "")
    if not EMAIL_RE.match(addr or ""):
        if addr:
            log.warning("MAIL_FROM is not a valid address; using SMTP_USER as the sender instead")
        fallback = settings.gmail_user if settings.email_provider == "gmail_api" else settings.smtp_user
        addr = fallback if EMAIL_RE.match(fallback or "") else ""
    return formataddr((name or "TrustVault", addr)), addr


def send_email(to: str, subject: str, body: str) -> None:
    provider = settings.email_provider
    try:
        if provider == "outbox":
            return _outbox("email", to, body)
        sender_header, sender_addr = _sender()
        if provider == "gmail_api":
            if not (settings.gmail_client_id and settings.gmail_client_secret and
                    settings.gmail_refresh_token and settings.gmail_user and sender_addr):
                raise DeliveryError("Gmail API is not configured")
            # Exchange the long-lived refresh token for a short-lived access token.
            from urllib.parse import urlencode
            token_req = urllib.request.Request(
                "https://oauth2.googleapis.com/token",
                data=urlencode({
                    "client_id": settings.gmail_client_id,
                    "client_secret": settings.gmail_client_secret,
                    "refresh_token": settings.gmail_refresh_token,
                    "grant_type": "refresh_token",
                }).encode("ascii"),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(token_req, timeout=15, context=ssl.create_default_context()) as resp:
                    token_data = json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                # Log Google's safe OAuth error code/description, never request credentials.
                try:
                    error_payload = json.loads(exc.read().decode("utf-8"))
                    oauth_error = error_payload.get("error", "unknown")
                    oauth_description = error_payload.get("error_description", "")
                    log.error(
                        "Gmail OAuth rejected refresh-token exchange: %s — %s",
                        str(oauth_error)[:100],
                        str(oauth_description)[:300],
                    )
                except Exception:
                    log.error("Gmail OAuth token request failed (HTTP %s)", exc.code)
                raise DeliveryError(f"Gmail OAuth token request failed (HTTP {exc.code})") from exc
            except urllib.error.URLError as exc:
                raise DeliveryError(f"Gmail OAuth token request failed: {exc.reason}") from exc
            access_token = token_data.get("access_token")
            if not access_token:
                raise DeliveryError("Gmail OAuth did not return an access token")
            msg = EmailMessage()
            msg["From"], msg["To"], msg["Subject"] = sender_header, to, subject
            msg.set_content(body)
            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")
            return _http_post(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
                data=json.dumps({"raw": raw}).encode("utf-8"),
                headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            )
        if provider == "twilio":
            if not (settings.twilio_api_key_sid and settings.twilio_api_key_secret and sender_addr):
                raise DeliveryError("Twilio Email is not configured")
            credentials = base64.b64encode(
                f"{settings.twilio_api_key_sid}:{settings.twilio_api_key_secret}".encode("utf-8")
            ).decode("ascii")
            escaped_body = html.escape(body).replace("\\n", "<br>")
            payload = {
                "from": {"address": sender_addr, "name": "TrustVault"},
                "to": [{"address": to}],
                "content": {"subject": subject, "text": body, "html": f"<p>{escaped_body}</p>"},
            }
            return _http_post(
                "https://comms.twilio.com/v1/Emails",
                data=json.dumps(payload).encode(),
                headers={"Authorization": f"Basic {credentials}", "Content-Type": "application/json"},
            )
        if provider == "sendgrid":
            if not (settings.sendgrid_api_key and sender_addr):
                raise DeliveryError("SendGrid is not configured")
            payload = {"personalizations": [{"to": [{"email": to}]}], "from": {"email": sender_addr},
                       "subject": subject, "content": [{"type": "text/plain", "value": body}]}
            return _http_post("https://api.sendgrid.com/v3/mail/send", data=json.dumps(payload).encode(),
                              headers={"Authorization": f"Bearer {settings.sendgrid_api_key}",
                                       "Content-Type": "application/json"})
        if not (settings.smtp_host and sender_addr):
            raise DeliveryError("SMTP is not configured")
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = sender_header, to, subject
        msg.set_content(body)
        ctx = ssl.create_default_context()
        if settings.smtp_port == 465:
            with smtplib.SMTP_SSL(settings.smtp_host, 465, context=ctx, timeout=20) as s:
                if settings.smtp_user:
                    s.login(settings.smtp_user, settings.smtp_password)
                s.send_message(msg, from_addr=sender_addr, to_addrs=[to])
        else:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as s:
                if settings.smtp_starttls:
                    s.starttls(context=ctx)
                if settings.smtp_user:
                    s.login(settings.smtp_user, settings.smtp_password)
                s.send_message(msg, from_addr=sender_addr, to_addrs=[to])
    except DeliveryError:
        raise
    except Exception as exc:  # smtplib / socket errors
        log.error("email delivery failed: %s: %s", type(exc).__name__, exc)
        raise DeliveryError("email delivery failed") from exc
