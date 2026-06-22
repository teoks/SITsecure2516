from pathlib import Path
from tempfile import TemporaryDirectory
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import create_app, db_session
from app.models import Base


class TestConfig:
    SECRET_KEY = "test-secret"
    DATABASE_URL = "sqlite:///:memory:"
    TESTING = True
    REQUIRE_STRONG_SECRET = False
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
    RATELIMIT_ENABLED = False
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_DEFAULT = "200 per day;50 per hour"
    LOG_FILE = "logs/test_app.log"


def extract_csrf(html):
    marker = 'name="_csrf_token" value="'
    start = html.index(marker) + len(marker)
    end = html.index('"', start)
    return html[start:end]


def main():
    app = create_app(TestConfig)
    with app.app_context():
        Base.metadata.create_all(bind=app.db_engine)
    client = app.test_client()

    page = client.get("/register")
    csrf = extract_csrf(page.get_data(as_text=True))
    response = client.post("/register", data={
        "_csrf_token": csrf,
        "username": "alice",
        "email": "alice@example.edu",
        "password": "StrongPass!2026",
        "confirm_password": "StrongPass!2026",
    }, follow_redirects=True)
    assert response.status_code == 200

    page = client.get("/login")
    csrf = extract_csrf(page.get_data(as_text=True))
    response = client.post("/login", data={
        "_csrf_token": csrf,
        "identifier": "alice",
        "password": "StrongPass!2026",
    }, follow_redirects=True)
    assert response.status_code == 200

    page = client.get("/posts/new")
    csrf = extract_csrf(page.get_data(as_text=True))
    response = client.post("/posts/new", data={
        "_csrf_token": csrf,
        "title": "Secure coding revision",
        "category": "Security",
        "body": "Discuss SQL injection, XSS, and CSRF defenses.",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert "Secure coding revision" in response.get_data(as_text=True)

    response = client.post("/posts/new", data={
        "title": "Missing CSRF",
        "category": "Security",
        "body": "This should fail.",
    })
    assert response.status_code == 403
    print("Smoke test passed.")


if __name__ == "__main__":
    main()
