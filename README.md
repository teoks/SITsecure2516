# Secure Student Discussion Forum

A web-based discussion forum built for the Secure Software Design module (Group 6). The application gives students a place to post questions, discuss course material, and share resources, while demonstrating how common web application threats can be mitigated at the design and implementation level.

The stack is deliberately small: Flask with server-rendered templates, SQLAlchemy on top of a local SQLite database, and Gunicorn behind Nginx for deployment. Only local accounts are supported; there is no OAuth or third-party login.

## Features

**Students**
- Register with email verification, log in, and manage their own profile
- Create, edit, and soft-delete discussion posts and comments
- Search posts by keyword and filter by category
- Bookmark useful posts to a private saved list
- Report posts or comments for moderation

**Administrators**
- Dashboard with user, post, and report statistics
- Review and resolve content reports
- Pin or lock discussions
- Change user roles, verify accounts, and deactivate abusive users

Deleted content is soft-deleted (`is_deleted` / `deleted_at`) rather than removed, so moderators can still review it if needed.

## Security Controls

Security decisions in this project trace back to the threat model produced in Deliverable 1. The main controls implemented in code are:

| Area | Control |
| --- | --- |
| Password storage | scrypt hashing via Werkzeug; strong minimum length and complexity rules |
| Brute force | Login rate limiting plus temporary account lockout after repeated failed attempts |
| User enumeration | A dummy hash is compared when a username does not exist, so login timing does not reveal valid accounts |
| CSRF | A single `before_request` hook validates a session token on every POST/PUT/PATCH/DELETE |
| Access control | `admin_required`, `verified_required`, and owner-or-admin checks on all protected routes |
| Sessions | HttpOnly and SameSite cookies, short session lifetime, and single-session enforcement (logging in elsewhere invalidates the old session) |
| Tokens | Email verification and password reset tokens are stored as SHA-256 hashes with expiry timestamps |
| XSS | Jinja auto-escaping, a restrictive Content Security Policy, and no raw HTML input anywhere |
| Open redirects | Redirect targets and referrers are validated before use |
| Headers | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and HSTS when HTTPS is enabled |
| Auditing | Security events are written to a hash-chained audit log; the chain can be verified from the CLI |
| Abuse limits | Per-route rate limits on sensitive actions and a strict request size cap |

The attack surface is kept small on purpose: no file uploads, no public JSON API, and a fixed set of post categories.

## Project Structure

```
app/
  __init__.py     Application factory, CLI commands, error handlers
  auth.py         Registration, login, profile, password reset
  forum.py        Posts, comments, search, bookmarks, reports
  admin.py        Admin dashboard and moderation routes
  security.py     CSRF, validators, decorators, audit logging, headers
  models.py       SQLAlchemy models
  mailer.py       SMTP email for verification and password reset
  config.py       Configuration loaded from environment / .env
deployment/       Nginx config, systemd unit, deployment script
tests/            Smoke test, unit tests, Selenium UI tests
```

## Getting Started

The application is hosted on an AWS EC2 instance and served over HTTPS by Nginx, which reverse-proxies to Gunicorn. Deployment is fully automated: pushing to `main` triggers the GitHub Actions pipeline, which runs the security scans and test suites and then deploys the validated commit to EC2. See the **Deployment** section below for details.

## Configuration

Settings are read from environment variables, with a `.env` file in the project root as a fallback. The most relevant ones:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | dev placeholder | Must be set to a strong value in production; the app refuses to start otherwise |
| `DATABASE_URL` | `sqlite:///instance/forum.db` | Database location |
| `APP_ENV` | `development` | Set to `production` to enable secure cookies and strict checks |
| `SESSION_HOURS` | `2` | Session lifetime |
| `LOGIN_FAILURE_LIMIT` / `LOGIN_LOCK_MINUTES` | `5` / `15` | Lockout policy |
| `MAIL_ENABLED`, `MAIL_SERVER`, `MAIL_USERNAME`, `MAIL_PASSWORD` | off | SMTP delivery for verification and reset emails |
| `APP_BASE_URL` | `http://127.0.0.1:5000` | Public URL used in emailed links |
| `RATELIMIT_ENABLED` | `1` | Toggles Flask-Limiter |

Do not commit `.env`, the `instance/` folder, or database files; they are excluded via `.gitignore`.

## Testing

Development dependencies are separate from runtime ones and are listed in `requirements-dev.txt`. Unit tests live in `tests/test_app_basic.py` and a smoke test in `tests/smoke_test.py`.

Selenium UI tests (`tests/test_selenium_ui.py`) need a local browser driver and a running instance of the application.

## Deployment

Production runs on a single AWS EC2 instance. Nginx terminates TLS and serves the site over HTTPS, redirecting all HTTP traffic to HTTPS, and proxies to Gunicorn, which is not exposed publicly. The service runs under systemd as a dedicated low-privilege user with `NoNewPrivileges`, `PrivateTmp`, and `ProtectSystem=full`.

See the `deployment/` directory:

- `nginx-secure-student-forum.conf` — reverse proxy, security headers, 1 MB body limit
- `secure-student-forum.service` — hardened systemd unit
- `deploy_secure_student_forum.sh` — provisioning script

The instance's `.env` sets `APP_ENV=production`, a strong `SECRET_KEY`, and `SESSION_COOKIE_SECURE=1`, enabling secure cookies and strict configuration checks.

Every push to `main` runs the CI/CD pipeline (`.github/workflows/deploy.yml`): security scans (Bandit, pip-audit, OWASP Dependency-Check, detect-secrets), unit tests, and Selenium UI tests must all pass before the exact validated commit is deployed to EC2, where the deployment script verifies services, ports, HTTPS, security headers, and the firewall before completing.