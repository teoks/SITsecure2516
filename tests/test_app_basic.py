import os
import tempfile

import pytest

from app import create_app, db_session
from app.models import AuditLog, Base, User
from werkzeug.security import generate_password_hash


def build_isolated_test_config(database_url, log_file):
    """Create explicit test settings without inheriting production values."""

    class IsolatedTestConfig:
        APP_ENV = "testing"
        TESTING = True
        DEBUG = False

        SECRET_KEY = "test-only-secret-key"
        REQUIRE_STRONG_SECRET = False
        DATABASE_URL = database_url
        AUTO_CREATE_DB = False

        SESSION_COOKIE_NAME = "test-session"
        SESSION_COOKIE_HTTPONLY = True
        SESSION_COOKIE_SAMESITE = "Lax"
        SESSION_COOKIE_SECURE = False
        REMEMBER_COOKIE_HTTPONLY = True
        REMEMBER_COOKIE_SAMESITE = "Lax"
        REMEMBER_COOKIE_SECURE = False
        PERMANENT_SESSION_LIFETIME = 7200
        SINGLE_SESSION_PER_USER = True

        MAX_CONTENT_LENGTH = 1024 * 1024
        PASSWORD_MIN_LENGTH = 12
        LOGIN_FAILURE_LIMIT = 5
        LOGIN_LOCK_MINUTES = 15

        USE_PROXY_FIX = False

        EMAIL_VERIFICATION_REQUIRED = False
        EMAIL_TOKEN_MINUTES = 60
        PASSWORD_RESET_MINUTES = 30
        DEV_SHOW_TOKENS = True

        MAIL_ENABLED = False
        MAIL_SERVER = ""
        MAIL_PORT = 587
        MAIL_USE_TLS = False
        MAIL_USE_SSL = False
        MAIL_USERNAME = ""
        MAIL_PASSWORD = ""
        MAIL_DEFAULT_SENDER = "test@example.invalid"
        APP_BASE_URL = "http://localhost"

        RATELIMIT_ENABLED = False
        RATELIMIT_STORAGE_URI = "memory://"
        RATELIMIT_DEFAULT = "200 per day;50 per hour"

        LOG_FILE = log_file

    return IsolatedTestConfig


def cleanup_test_app(app, db_path, log_path):
    """Release database and log-file handles before deleting test files."""

    with app.app_context():
        db_session.remove()
        Base.metadata.drop_all(bind=app.db_engine)
        db_session.remove()

    app.db_engine.dispose()

    if app.audit_engine is not None:
        app.audit_engine.dispose()

    # RotatingFileHandler keeps the log file open on Windows. Remove and
    # close only the handler created for this isolated test application.
    expected_log_path = os.path.normcase(os.path.abspath(log_path))

    for handler in list(app.logger.handlers):
        handler_path = getattr(handler, "baseFilename", None)

        if (
            handler_path
            and os.path.normcase(os.path.abspath(handler_path))
            == expected_log_path
        ):
            app.logger.removeHandler(handler)
            handler.flush()
            handler.close()

    if os.path.exists(db_path):
        os.unlink(db_path)

    if os.path.exists(log_path):
        os.unlink(log_path)


@pytest.fixture
def client():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    log_path = f"{db_path}.log"

    test_config = build_isolated_test_config(
        database_url=f"sqlite:///{db_path}",
        log_file=log_path,
    )
    app = create_app(test_config)

    with app.app_context():
        Base.metadata.create_all(bind=app.db_engine)

    with app.test_client() as test_client:
        yield test_client

    cleanup_test_app(app, db_path, log_path)


def test_client_uses_isolated_test_configuration(client):
    app = client.application
    database_url = app.config["DATABASE_URL"]

    assert app.config["TESTING"] is True
    assert app.config["APP_ENV"] == "testing"
    assert app.config["USE_PROXY_FIX"] is False
    assert app.config["MAIL_ENABLED"] is False
    assert app.config["RATELIMIT_ENABLED"] is False
    assert app.config["SESSION_COOKIE_SECURE"] is False
    assert database_url.startswith("sqlite:///")
    assert not database_url.endswith("/instance/forum.db")
    assert not database_url.endswith("\\instance\\forum.db")


def test_homepage_loads(client):
    response = client.get("/")
    assert response.status_code in [200, 302]


def test_login_page_loads(client):
    response = client.get("/login")
    assert response.status_code in [200, 302]


def test_register_page_loads(client):
    response = client.get("/register")
    assert response.status_code in [200, 302]


def test_admin_requires_login(client):
    response = client.get("/admin/")
    assert response.status_code in [302, 401, 403]


def extract_csrf(html):
    marker = 'name="_csrf_token" value="'
    start = html.index(marker) + len(marker)
    end = html.index('"', start)
    return html[start:end]


def login(client, identifier="alice", password="StrongPass!2026"):
    page = client.get("/login")
    csrf = extract_csrf(page.get_data(as_text=True))
    return client.post("/login", data={
        "_csrf_token": csrf,
        "identifier": identifier,
        "password": password,
    })


def test_new_login_invalidates_previous_session(client):
    with client.application.app_context():
        db_session.add(User(
            username="alice",
            email="alice@example.edu",
            password_hash=generate_password_hash("StrongPass!2026", method="scrypt"),
            account_active=True,
            email_verified=True,
        ))
        db_session.commit()

    first_client = client.application.test_client()
    second_client = client.application.test_client()

    assert login(first_client).status_code == 302
    assert first_client.get("/profile").status_code == 200

    assert login(second_client).status_code == 302

    response = first_client.get("/profile", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
    assert second_client.get("/profile").status_code == 200


def test_audit_event_trusts_only_last_proxy_hop(client):
    from app.security import audit_event
    from werkzeug.middleware.proxy_fix import ProxyFix

    @client.application.route("/audit-ip-test")
    def audit_ip_test():
        audit_event("ip_test")
        return "ok"

    original_wsgi_app = client.application.wsgi_app

    client.application.wsgi_app = ProxyFix(
        original_wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=0,
        x_port=0,
        x_prefix=0,
    )

    try:
        response = client.get(
            "/audit-ip-test",
            headers={
                "X-Forwarded-For": "203.0.113.10, 10.0.0.5",
                "X-Forwarded-Proto": "https",
            },
        )
    finally:
        client.application.wsgi_app = original_wsgi_app

    assert response.status_code == 200

    with client.application.app_context():
        log = db_session.query(AuditLog).filter_by(event_type="ip_test").one()
        assert log.ip_address == "10.0.0.5"


def test_audit_event_falls_back_to_remote_addr(client):
    from app.security import audit_event

    @client.application.route("/audit-remote-ip-test")
    def audit_remote_ip_test():
        audit_event("remote_ip_test")
        return "ok"

    response = client.get(
        "/audit-remote-ip-test",
        environ_base={"REMOTE_ADDR": "198.51.100.20"},
    )

    assert response.status_code == 200
    with client.application.app_context():
        log = db_session.query(AuditLog).filter_by(event_type="remote_ip_test").one()
        assert log.ip_address == "198.51.100.20"


def test_audit_event_concurrent_writes_keep_chain_intact(client):
    import threading

    from app.security import _audit_hash, audit_event

    app = client.application
    errors = []

    def worker(i):
        try:
            with app.test_request_context("/"):
                audit_event(f"concurrent_{i}")
        except Exception as exc:  # pragma: no cover - surfaced via assertion below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors

    with app.app_context():
        logs = db_session.query(AuditLog).order_by(AuditLog.id.asc()).all()
        assert len(logs) == 20

        previous_hash = None
        for log in logs:
            expected = _audit_hash(
                previous_hash,
                log.actor_user_id,
                log.event_type,
                log.details,
                log.ip_address,
                log.user_agent,
                log.created_at,
            )
            assert log.previous_hash == previous_hash, f"chain broken at id {log.id}"
            assert log.entry_hash == expected, f"hash mismatch at id {log.id}"
            previous_hash = log.entry_hash


def test_500_handler_returns_clean_page_and_rolls_back():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    log_path = f"{db_path}.log"

    test_config = build_isolated_test_config(
        database_url=f"sqlite:///{db_path}",
        log_file=log_path,
    )
    app = create_app(test_config)
    app.config["PROPAGATE_EXCEPTIONS"] = False

    @app.route("/cause-error-test")
    def cause_error_test():
        raise Exception("Deliberate test error")

    with app.app_context():
        Base.metadata.create_all(bind=app.db_engine)

    with app.test_client() as test_client:
        response = test_client.get("/cause-error-test")

        assert response.status_code == 500

        body = response.get_data(as_text=True)
        assert "Something went wrong" in body
        assert "Traceback" not in body
        assert "Deliberate test error" not in body

    cleanup_test_app(app, db_path, log_path)


def test_audit_event_logs_storage_failure(client, monkeypatch, caplog):
    import logging
    import app.security as security

    class FailingAuditSession:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            raise RuntimeError("simulated audit database failure")

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    monkeypatch.setattr(security, "Session", FailingAuditSession)

    @client.application.route("/audit-failure-test")
    def audit_failure_test():
        security.audit_event("audit_failure_test")
        return "ok"

    with caplog.at_level(logging.ERROR):
        response = client.get("/audit-failure-test")

    assert response.status_code == 200
    assert "audit_event_failed event=audit_failure_test" in caplog.text
    assert "simulated audit database failure" in caplog.text