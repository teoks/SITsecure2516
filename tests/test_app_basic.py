import os
import tempfile

import pytest

from app import create_app, db_session
from app.models import Base, User
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
