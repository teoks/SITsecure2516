import os
import tempfile

import pytest

from app import create_app, db_session
from app.models import Base


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