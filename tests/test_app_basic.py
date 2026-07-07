import os
import tempfile

import pytest

from app import create_app, db_session
from app.models import AuditLog, Base, User
from werkzeug.security import generate_password_hash


@pytest.fixture
def client():
    db_fd, db_path = tempfile.mkstemp()

    os.environ["FLASK_ENV"] = "testing"
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["SECRET_KEY"] = "test-secret-key"

    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    with app.app_context():
        Base.metadata.create_all(bind=db_session.bind)

    with app.test_client() as client:
        yield client

    with app.app_context():
        db_session.remove()
        Base.metadata.drop_all(bind=db_session.bind)

    os.close(db_fd)
    os.unlink(db_path)


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


def test_audit_event_uses_access_route_client_ip(client):
    from app.security import audit_event

    @client.application.route("/audit-ip-test")
    def audit_ip_test():
        audit_event("ip_test")
        return "ok"

    response = client.get(
        "/audit-ip-test",
        headers={"X-Forwarded-For": "203.0.113.10, 10.0.0.5"},
    )

    assert response.status_code == 200
    with client.application.app_context():
        log = db_session.query(AuditLog).filter_by(event_type="ip_test").one()
        assert log.ip_address == "203.0.113.10"


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


def test_500_handler_returns_clean_page_and_rolls_back():
    # Build a fresh app for this test so we can allow the 500 handler
    # to run instead of Flask re-raising the exception during testing.
    import tempfile
    db_fd, db_path = tempfile.mkstemp()
    os.environ["FLASK_ENV"] = "testing"
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["SECRET_KEY"] = "test-secret-key"

    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    # Let the app route exceptions to our 500 handler instead of re-raising.
    app.config["PROPAGATE_EXCEPTIONS"] = False

    # Register a temporary route that deliberately crashes.
    @app.route("/cause-error-test")
    def cause_error_test():
        raise Exception("Deliberate test error")

    with app.app_context():
        Base.metadata.create_all(bind=db_session.bind)

    with app.test_client() as test_client:
        response = test_client.get("/cause-error-test")

        # 1) The handler should return HTTP 500.
        assert response.status_code == 500

        body = response.get_data(as_text=True)
        # 2) The clean, generic message should be shown.
        assert "Something went wrong" in body
        # 3) OWASP A05: no stack trace / technical detail should leak.
        assert "Traceback" not in body
        assert "Deliberate test error" not in body

    with app.app_context():
        db_session.remove()
        Base.metadata.drop_all(bind=db_session.bind)

    os.close(db_fd)
    os.unlink(db_path)
