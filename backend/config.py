"""Runtime settings, read once from the environment (see .env.example)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _database_url() -> str:
    url = os.getenv("DATABASE_URL", "").strip()
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


@dataclass(frozen=True)
class Settings:
    app_env: str = os.getenv("APP_ENV", "production").lower()
    database_url: str = _database_url()
    jwt_secret: str = os.getenv("JWT_SECRET", "")
    otp_pepper: str = os.getenv("OTP_PEPPER", "")
    passcode_pepper: str = os.getenv("PASSCODE_PEPPER", "")

    cookie_secure: bool = _bool("COOKIE_SECURE", True)
    allowed_origins: tuple[str, ...] = tuple(
        o.strip().rstrip("/") for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:8000").split(",") if o.strip()
    )
    trusted_proxy: bool = _bool("TRUST_PROXY_HEADERS", False)

    session_minutes: int = _int("SESSION_IDLE_MINUTES", 15)
    otp_ttl_seconds: int = 300
    otp_max_attempts: int = 5
    lockout_threshold: int = 5
    lockout_minutes: int = 15
    max_upload_bytes: int = 10 * 1024 * 1024

    email_provider: str = os.getenv("EMAIL_PROVIDER", "smtp").lower()
    smtp_host: str = os.getenv("SMTP_HOST", "")
    smtp_port: int = _int("SMTP_PORT", 587)
    smtp_user: str = os.getenv("SMTP_USER", "")
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    smtp_starttls: bool = _bool("SMTP_STARTTLS", True)
    mail_from: str = os.getenv("MAIL_FROM", "")
    sendgrid_api_key: str = os.getenv("SENDGRID_API_KEY", "")
    twilio_api_key_sid: str = os.getenv("TWILIO_API_KEY_SID", "")
    twilio_api_key_secret: str = os.getenv("TWILIO_API_KEY_SECRET", "")
    otp_outbox_path: str = os.getenv("OTP_OUTBOX_PATH", "/app/data/otp_outbox.log")

    initial_credentials_file: str = os.getenv("INITIAL_CREDENTIALS_FILE", "/app/data/initial_credentials.txt")
    frontend_dir: str = os.getenv("FRONTEND_DIR", os.path.join(os.path.dirname(__file__), "..", "frontend"))

    rate_signup_per_10min: int = _int("RATE_SIGNUP_PER_10MIN", 10)
    rate_login_per_min: int = _int("RATE_LOGIN_PER_MIN", 30)

    seed_emails: dict = field(default_factory=lambda: {
        u: os.getenv(f"SEED_{u.upper()}_EMAIL", "")
        for u in ("Manikonda_Rohith", "Naveen", "Gowtham", "Krishna", "Keerthi")
    })

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    def validate(self) -> None:
        problems = []
        if not self.database_url.startswith("postgresql+psycopg://"):
            problems.append("DATABASE_URL must be a PostgreSQL URL using Psycopg 3")
        for name in ("jwt_secret", "otp_pepper", "passcode_pepper"):
            if len(getattr(self, name)) < 32:
                problems.append(f"{name.upper()} must be at least 32 characters")
        if self.is_production:
            if not self.cookie_secure:
                problems.append("COOKIE_SECURE must be true in production")
            if self.email_provider == "outbox":
                problems.append("the 'outbox' OTP provider is for development only")
        if self.email_provider not in {"smtp", "sendgrid", "twilio", "outbox"}:
            problems.append("EMAIL_PROVIDER must be smtp, sendgrid, twilio or outbox")
        if problems:
            raise RuntimeError("Unsafe or incomplete configuration:\n  - " + "\n  - ".join(problems))


settings = Settings()
