import os
from pathlib import Path
import shutil
from datetime import datetime

import click
from flask import Flask, render_template
from flask_login import LoginManager
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import scoped_session, sessionmaker
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash

from .config import Config
from .models import Base, User

from datetime import timezone, timedelta

# Thread-local SQLAlchemy session used by the application.
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, future=True))

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"


def _ensure_schema_compatibility(engine):
    """Apply small additive schema updates for deployments without migrations."""
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return
    user_columns = {column["name"] for column in inspector.get_columns("users")}
    statements = []
    if "active_session_token_hash" not in user_columns:
        statements.append("ALTER TABLE users ADD COLUMN active_session_token_hash VARCHAR(128)")
    if "active_session_started_at" not in user_columns:
        statements.append("ALTER TABLE users ADD COLUMN active_session_started_at DATETIME")
    if not statements:
        return
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def create_app(config_object=Config):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_object)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    if app.config.get("REQUIRE_STRONG_SECRET") and str(app.config.get("SECRET_KEY", "")).startswith("dev-"):
        raise RuntimeError("Set a strong SECRET_KEY environment variable before running in production.")

    database_url = app.config["DATABASE_URL"]
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, future=True, pool_pre_ping=True, connect_args=connect_args)
    db_session.configure(bind=engine)
    app.db_engine = engine

    app.audit_engine = None
    # A separate sqlite:///:memory: connection is a distinct, empty database -
    # it can't see the main engine's tables, so the dedicated engine below
    # would silently write audit rows nobody can read. Skip it for in-memory
    # DBs (used by tests/smoke_test.py) and just share the main engine there.
    if database_url.startswith("sqlite") and ":memory:" not in database_url:
        # SQLite's default deferred transactions only take a write lock at the
        # first write statement, not at the start of the transaction. That
        # leaves a window where two connections can both read the same
        # "latest audit log row" before either writes, breaking the hash
        # chain (OWASP A08). This dedicated engine is used only by
        # audit_event() so every transaction on it starts with BEGIN
        # IMMEDIATE, taking the write lock up front - giving with_for_update()
        # a real lock to acquire even on SQLite, and holding across separate
        # Gunicorn worker processes too since it's an OS-level file lock, not
        # an in-process one. The main engine above is untouched, so ordinary
        # reads/writes elsewhere keep SQLite's normal concurrent-reader
        # behavior.
        audit_engine = create_engine(database_url, future=True, pool_pre_ping=True, connect_args=connect_args)

        @event.listens_for(audit_engine, "connect")
        def _sqlite_manual_transactions(dbapi_connection, connection_record):
            dbapi_connection.isolation_level = None

        @event.listens_for(audit_engine, "begin")
        def _sqlite_begin_immediate(conn):
            conn.exec_driver_sql("BEGIN IMMEDIATE")

        app.audit_engine = audit_engine
    if app.config.get("AUTO_CREATE_DB"):
        Base.metadata.create_all(bind=engine)
    _ensure_schema_compatibility(engine)

    if app.config.get("USE_PROXY_FIX"):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    login_manager.init_app(app)

    from .security import init_security
    init_security(app)

    from .auth import bp as auth_bp
    from .forum import bp as forum_bp
    from .admin import bp as admin_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(forum_bp)
    app.register_blueprint(admin_bp)

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db_session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        db_session.remove()

    @app.cli.command("init-db")
    def init_db_command():
        """Create database tables."""
        Base.metadata.create_all(bind=engine)
        click.echo("Initialized the database.")

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True, help="Admin username")
    @click.option("--email", prompt=True, help="Admin email address")
    @click.password_option("--password", confirmation_prompt=True, help="Admin password")
    def create_admin_command(username, email, password):
        """Create an administrator account without using OAuth or third-party auth."""
        from .security import normalize_email, normalize_username, validate_email, validate_password, validate_username

        Base.metadata.create_all(bind=engine)
        username = normalize_username(username)
        email = normalize_email(email)
        errors = []
        if not validate_username(username):
            errors.append("Username must be 3-32 characters and may contain letters, numbers, dot, underscore, or hyphen.")
        if not validate_email(email):
            errors.append("Email address is invalid.")
        errors.extend(validate_password(password, username=username, email=email))
        if errors:
            for error in errors:
                click.echo(f"Error: {error}")
            raise click.Abort()
        existing = db_session.query(User).filter((User.username == username) | (User.email == email)).first()
        if existing:
            click.echo("An account with that username or email already exists.")
            raise click.Abort()
        admin = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password, method="scrypt"),
            role="admin",
            account_active=True,
            email_verified=True,
        )
        db_session.add(admin)
        db_session.commit()
        click.echo(f"Created admin user: {username}")


    @app.cli.command("backup-db")
    @click.option("--output-dir", default="backups", help="Directory where the backup file will be written")
    def backup_db_command(output_dir):
        """Create a timestamped SQLite database backup for recovery testing."""
        if not database_url.startswith("sqlite"):
            click.echo("backup-db currently supports the SQLite coursework database only.")
            raise click.Abort()
        db_path = database_url.replace("sqlite:///", "", 1)
        source = Path(db_path)
        if not source.exists():
            click.echo("Database does not exist yet. Run flask init-db first.")
            raise click.Abort()
        backup_dir = Path(output_dir)
        backup_dir.mkdir(parents=True, exist_ok=True)
        target = backup_dir / f"forum_backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.db"
        shutil.copy2(source, target)
        click.echo(f"Backup created: {target}")

    @app.cli.command("verify-audit-log")
    def verify_audit_log_command():
        """Verify the audit log hash chain has not been tampered with."""
        from .models import AuditLog
        from .security import _audit_hash
        previous_hash = None
        for log in db_session.query(AuditLog).order_by(AuditLog.id.asc()).all():
            expected = _audit_hash(previous_hash, log.actor_user_id, log.event_type, log.details, log.ip_address, log.user_agent, log.created_at)
            if log.previous_hash != previous_hash or log.entry_hash != expected:
                click.echo(f"Audit chain mismatch at log id {log.id}")
                raise click.Abort()
            previous_hash = log.entry_hash
        click.echo("Audit log hash chain verified.")

    @app.cli.command("attack-surface")
    def attack_surface_command():
        """Print the deliberately exposed route surface for security review."""
        sensitive_methods = {"POST", "PUT", "PATCH", "DELETE"}
        click.echo("Application route attack surface:")
        for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
            if rule.endpoint == "static":
                continue
            methods = sorted(m for m in rule.methods if m not in {"HEAD", "OPTIONS"})
            protection = "CSRF required" if any(m in sensitive_methods for m in methods) else "read-only GET"
            if rule.rule.startswith("/admin"):
                protection += "; admin_required"
            elif any(part in rule.rule for part in ("/posts/new", "/saved", "/bookmark", "/comments", "/report")):
                protection += "; login/email verification required"
            click.echo(f"{','.join(methods):10s} {rule.rule:45s} {protection}")
        click.echo("Minimal surface controls: no file uploads, no public JSON API, no OAuth callbacks, fixed categories, POST-only state changes, CSRF on all state changes.")

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(413)
    def request_too_large(error):
        return render_template("errors/413.html"), 413

    @app.errorhandler(500)
    def internal_server_error(error):
        # Roll back any pending/broken database transaction so a
        # half finished change cannot corrupt data or break later requests.
        db_session.rollback()

        # Log the real error server side for our own debugging.
        # OWASP A05: the user never sees this detail, it stays in server logs.
        app.logger.error("Internal server error: %s", error, exc_info=True)

        # Show the user a clean, generic page with no technical detail.
        return render_template("errors/500.html"), 500

    @app.template_filter("sgt")
    def sgt_filter(value):
        if value is None:
            return ""

        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        singapore_time = value.astimezone(timezone(timedelta(hours=8)))

        return singapore_time.strftime("%Y-%m-%d %H:%M")

    return app
