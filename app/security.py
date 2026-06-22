import hashlib
import logging
import re
import secrets
from datetime import datetime, timedelta
from functools import wraps
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlparse

from flask import abort, current_app, flash, redirect, request, session, url_for
from flask_login import current_user, login_required, logout_user
from werkzeug.security import generate_password_hash

from . import db_session
from .models import AuditLog

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DUMMY_PASSWORD_HASH = generate_password_hash("dummy-password-for-timing", method="scrypt")
limiter = None


def normalize_username(value):
    return (value or "").strip().lower()


def normalize_email(value):
    return (value or "").strip().lower()


def validate_username(value):
    return bool(USERNAME_RE.fullmatch(value or ""))


def validate_email(value):
    value = normalize_email(value)
    return bool(value and len(value) <= 255 and EMAIL_RE.fullmatch(value))


def validate_password(password, username="", email=""):
    errors = []
    password = password or ""
    username = (username or "").lower()
    email_user = (email or "").split("@")[0].lower()
    min_length = current_app.config.get("PASSWORD_MIN_LENGTH", 12) if current_app else 12
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters long.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r"\d", password):
        errors.append("Password must contain at least one number.")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("Password must contain at least one symbol.")
    lowered = password.lower()
    if username and username in lowered:
        errors.append("Password must not contain the username.")
    if email_user and email_user in lowered:
        errors.append("Password must not contain the email name.")
    return errors


def clean_text(value, max_length, required=True):
    value = (value or "").replace("\x00", "").strip()
    if required and not value:
        return None, "This field is required."
    if len(value) > max_length:
        return None, f"Maximum length is {max_length} characters."
    return value, None


def generate_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf_token(token):
    session_token = session.get("_csrf_token", "")
    return bool(token and session_token and secrets.compare_digest(str(token), str(session_token)))


def is_safe_redirect_target(target):
    if not target:
        return False
    parsed = urlparse(target)
    return not parsed.netloc and parsed.scheme in ("", "http", "https") and target.startswith("/")


def create_token_pair():
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_token(token):
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def rotate_user_session(user):
    token = secrets.token_urlsafe(32)
    user.active_session_token_hash = hash_token(token)
    user.active_session_started_at = datetime.utcnow()
    session["active_session_token"] = token
    db_session.commit()


def clear_user_session(user):
    token = session.get("active_session_token")
    if user and token and user.active_session_token_hash == hash_token(token):
        user.active_session_token_hash = None
        user.active_session_started_at = None
        db_session.commit()


def user_is_locked(user):
    if not user or not user.lock_until:
        return False
    if user.lock_until <= datetime.utcnow():
        user.failed_login_count = 0
        user.lock_until = None
        db_session.commit()
        return False
    return True


def record_failed_login(user):
    if not user:
        return
    now = datetime.utcnow()
    if user.lock_until and user.lock_until <= now:
        user.failed_login_count = 0
        user.lock_until = None
    user.failed_login_count = (user.failed_login_count or 0) + 1
    if user.failed_login_count >= current_app.config.get("LOGIN_FAILURE_LIMIT", 5):
        user.lock_until = now + timedelta(minutes=current_app.config.get("LOGIN_LOCK_MINUTES", 15))
    db_session.commit()


def reset_login_failures(user):
    user.failed_login_count = 0
    user.lock_until = None
    user.last_login_at = datetime.utcnow()
    db_session.commit()


def _audit_hash(previous_hash, actor_id, event_type, details, ip, ua, created_at):
    raw = f"{previous_hash or ''}|{actor_id or ''}|{event_type}|{details or ''}|{ip or ''}|{ua or ''}|{created_at.isoformat()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def audit_event(event_type, details=""):
    try:
        actor_id = int(current_user.get_id()) if getattr(current_user, "is_authenticated", False) else None
        ip = (request.headers.get("X-Forwarded-For", request.remote_addr or "")[:64])
        ua = (request.user_agent.string or "")[:255]
        created_at = datetime.utcnow()
        previous = db_session.query(AuditLog).order_by(AuditLog.id.desc()).first()
        previous_hash = previous.entry_hash if previous else None
        entry_hash = _audit_hash(previous_hash, actor_id, (event_type or "event")[:80], (details or "")[:1000], ip, ua, created_at)
        log = AuditLog(
            actor_user_id=actor_id,
            event_type=(event_type or "event")[:80],
            details=(details or "")[:1000],
            ip_address=ip,
            user_agent=ua,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
            created_at=created_at,
        )
        db_session.add(log)
        db_session.commit()
        current_app.logger.info("audit event=%s actor=%s details=%s hash=%s", event_type, actor_id, details, entry_hash)
    except Exception:
        db_session.rollback()


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def verified_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if current_app.config.get("EMAIL_VERIFICATION_REQUIRED") and not current_user.email_verified and not current_user.is_admin:
            flash("Please verify your email before posting, commenting, or reporting content.", "warning")
            return redirect(url_for("auth.profile"))
        return view(*args, **kwargs)
    return wrapped


def owner_or_admin(resource_user_id):
    return current_user.is_authenticated and (current_user.is_admin or current_user.id == resource_user_id)


def configure_logging(app):
    log_file = Path(app.config.get("LOG_FILE"))
    log_file.parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(log_file, maxBytes=512000, backupCount=5)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    handler.setLevel(logging.INFO)
    if not app.logger.handlers:
        app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)


def init_rate_limiter(app):
    global limiter
    if not app.config.get("RATELIMIT_ENABLED"):
        return None
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        defaults = [x.strip() for x in app.config.get("RATELIMIT_DEFAULT", "200 per day;50 per hour").split(";") if x.strip()]
        limiter = Limiter(get_remote_address, app=app, default_limits=defaults, storage_uri=app.config.get("RATELIMIT_STORAGE_URI"))
        return limiter
    except Exception as exc:
        app.logger.warning("Flask-Limiter is unavailable; route-level rate limiting disabled: %s", exc)
        limiter = None
        return None


def init_security(app):
    configure_logging(app)
    init_rate_limiter(app)

    @app.before_request
    def enforce_single_session():
        if not app.config.get("SINGLE_SESSION_PER_USER"):
            return None
        if request.endpoint == "static" or not getattr(current_user, "is_authenticated", False):
            return None
        token = session.get("active_session_token")
        if token and current_user.active_session_token_hash == hash_token(token):
            return None
        username = current_user.username
        audit_event("session_invalidated", username)
        logout_user()
        session.clear()
        if request.endpoint == "auth.login":
            return None
        flash("You were signed out because your account was opened in another browser.", "warning")
        if request.method == "GET":
            return redirect(url_for("auth.login"))
        abort(403)

    @app.before_request
    def csrf_protect():
        if request.endpoint == "static":
            return None
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            token = request.form.get("_csrf_token") or request.headers.get("X-CSRFToken")
            if not validate_csrf_token(token):
                app.logger.warning("csrf_failed ip=%s path=%s", request.remote_addr, request.path)
                abort(403)
        return None

    @app.context_processor
    def csrf_context():
        return {"csrf_token": generate_csrf_token}

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        )
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if getattr(current_user, "is_authenticated", False):
            response.headers.setdefault("Cache-Control", "no-store")
        return response
