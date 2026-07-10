import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB = BASE_DIR / "instance" / "forum.db"


def _load_env_file():
    """Load KEY=VALUE entries from .env without requiring python-dotenv.

    Existing environment variables always win. This keeps secrets on the EC2 host
    while allowing the application, Flask CLI, and Gunicorn to share one config file.
    """
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_env_file()


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me-before-deployment")
    DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DEFAULT_DB}")

    APP_ENV = os.environ.get("APP_ENV", os.environ.get("FLASK_ENV", "development")).lower()
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1" and APP_ENV != "production"
    REQUIRE_STRONG_SECRET = APP_ENV == "production"
    AUTO_CREATE_DB = os.environ.get("AUTO_CREATE_DB", "1" if APP_ENV != "production" else "0") == "1"

    SESSION_COOKIE_NAME = (
        "__Host-session"
        if APP_ENV == "production"
        else "student-forum-test-session"
    )
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "1" if APP_ENV == "production" else "0") == "1"
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = SESSION_COOKIE_SAMESITE
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    PERMANENT_SESSION_LIFETIME = timedelta(hours=int(os.environ.get("SESSION_HOURS", "2")))
    SINGLE_SESSION_PER_USER = os.environ.get("SINGLE_SESSION_PER_USER", "1") == "1"

    MAX_CONTENT_LENGTH = 1 * 1024 * 1024
    PASSWORD_MIN_LENGTH = 12
    LOGIN_FAILURE_LIMIT = int(os.environ.get("LOGIN_FAILURE_LIMIT", "5"))
    LOGIN_LOCK_MINUTES = int(os.environ.get("LOGIN_LOCK_MINUTES", "15"))
    USE_PROXY_FIX = os.environ.get("USE_PROXY_FIX", "1" if APP_ENV == "production" else "0") == "1"

    EMAIL_VERIFICATION_REQUIRED = os.environ.get("EMAIL_VERIFICATION_REQUIRED", "1") == "1"
    EMAIL_TOKEN_MINUTES = int(os.environ.get("EMAIL_TOKEN_MINUTES", "60"))
    PASSWORD_RESET_MINUTES = int(os.environ.get("PASSWORD_RESET_MINUTES", "30"))
    DEV_SHOW_TOKENS = os.environ.get("DEV_SHOW_TOKENS", "1" if APP_ENV != "production" else "0") == "1"

    # SMTP email. In production, set MAIL_ENABLED=1 and keep MAIL_PASSWORD in .env only.
    MAIL_ENABLED = os.environ.get("MAIL_ENABLED", "0") == "1"
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "1") == "1"
    MAIL_USE_SSL = os.environ.get("MAIL_USE_SSL", "0") == "1"
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "noreply@studentforum.local")
    APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://127.0.0.1:5000").rstrip("/")

    RATELIMIT_ENABLED = os.environ.get("RATELIMIT_ENABLED", "1") == "1"
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_DEFAULT = os.environ.get("RATELIMIT_DEFAULT", "200 per day;50 per hour")

    LOG_FILE = os.environ.get("LOG_FILE", str(BASE_DIR / "logs" / "app.log"))
