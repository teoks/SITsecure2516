# Secure Student Discussion Forum

A secure Flask and SQLite web application for student academic discussions. It supports local accounts only; no OAuth is used.

## Main features

- Student registration and login
- Account CRUD: create account, view profile, update profile/password, deactivate account
- Discussion post CRUD
- Comment CRUD
- Administrator dashboard
- Role-based access control for administrators and normal users
- Audit logging for important security events

## Security features included

- Password hashing with Werkzeug `scrypt`
- Password complexity checks
- Login brute-force protection with account lockout
- Flask-Login session management
- CSRF protection on all state-changing requests
- SQLAlchemy ORM queries to reduce SQL Injection risk
- Jinja auto-escaping and plain-text rendering to reduce XSS risk
- Input length validation for usernames, emails, posts, comments, and search
- Security response headers: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, optional HSTS
- Secure cookie settings: HttpOnly, SameSite=Lax, optional Secure flag for HTTPS
- Administrator checks for role changes and moderation actions
- Soft deletion for posts/comments/accounts to preserve auditability

## Local setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="dev-change-this-to-a-random-value"
flask --app wsgi init-db
flask --app wsgi create-admin
flask --app wsgi run
```

Open http://127.0.0.1:5000 in a browser.

## GitHub hosting

```bash
git init
git add .
git commit -m "Initial secure student forum"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/secure-student-forum.git
git push -u origin main
```

Do not commit the `instance/` directory, `.env`, database files, or real secrets.

## AWS EC2 deployment outline, Ubuntu 24.04.4 LTS

This deployment uses Nginx as the public reverse proxy and Gunicorn as the WSGI server. Flask's built-in development server must not be used for production.

### 1. EC2 security group

Allow only:

- SSH TCP 22 from your own IP address
- HTTP TCP 80 from the internet for testing or redirecting to HTTPS
- HTTPS TCP 443 from the internet after TLS is configured

Do not expose port 5000 or the Gunicorn Unix socket publicly.

### 2. Install system packages

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip nginx git
```

### 3. Clone and install

```bash
cd /home/ubuntu
git clone https://github.com/YOUR_USERNAME/secure-student-forum.git secure_student_forum
cd secure_student_forum
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
mkdir -p instance
export APP_ENV=production
export FLASK_ENV=production
export SECRET_KEY="REPLACE_WITH_LONG_RANDOM_SECRET"
export DATABASE_URL="sqlite:////home/ubuntu/secure_student_forum/instance/forum.db"
flask --app wsgi init-db
flask --app wsgi create-admin
```

### 4. Configure systemd

Copy `deployment/secure-student-forum.service` to `/etc/systemd/system/secure-student-forum.service`, then edit the environment variables and paths.

```bash
sudo cp deployment/secure-student-forum.service /etc/systemd/system/secure-student-forum.service
sudo systemctl daemon-reload
sudo systemctl enable --now secure-student-forum
sudo systemctl status secure-student-forum
```

### 5. Configure Nginx

Copy `deployment/nginx-secure-student-forum.conf` to `/etc/nginx/sites-available/secure-student-forum`, enable it, and reload Nginx.

```bash
sudo cp deployment/nginx-secure-student-forum.conf /etc/nginx/sites-available/secure-student-forum
sudo ln -s /etc/nginx/sites-available/secure-student-forum /etc/nginx/sites-enabled/secure-student-forum
sudo nginx -t
sudo systemctl reload nginx
```

### 6. Enable HTTPS

After a domain name points to the EC2 instance, install a certificate with your preferred certificate tool. Then set `SESSION_COOKIE_SECURE=1` in the systemd service and restart the service.

```bash
sudo systemctl restart secure-student-forum
```

## Maintenance notes

- Back up the SQLite database before updates.
- Rotate `SECRET_KEY` only with a planned logout window because it invalidates active sessions.
- Review audit logs after repeated login failures or admin actions.
- Keep OS packages and Python dependencies updated.

## Hardened security features added

This version includes additional security enhancements beyond the baseline forum requirements:

- HTTPS-ready secure cookie configuration for production.
- Optional `Flask-Limiter` rate limiting for login, registration, password reset, post/comment creation, and reports.
- Email verification before normal users can post, comment, or report content.
- Time-limited password reset tokens stored as hashes, not raw tokens.
- User reporting workflow for posts and comments.
- Admin moderation report queue at `/admin/reports`.
- Audit log hash chaining and a verification command.
- SQLite backup command for recovery testing.
- Stricter Content Security Policy and standard browser security headers.
- Rotating server-side application logs.

### Local VM notes for email verification

For coursework/local VM testing, the app does not actually send email. In development mode it displays the verification/reset link as a flash message after registration, resend verification, or password reset request.

```bash
export APP_ENV=development
export EMAIL_VERIFICATION_REQUIRED=1
export SESSION_COOKIE_SECURE=0
```

### Useful security commands

```bash
flask backup-db
flask verify-audit-log
```

See `docs/SECURITY_ENHANCEMENTS.md` and `docs/LOCAL_VM_TESTING_ENHANCED.md` for details.

## Advanced security use cases

This hardened version includes additional advanced use cases while keeping attack surface small:

- Admin pinned posts.
- Admin locked discussions.
- Private saved posts for verified users.
- Approved academic category allowlist.
- `flask attack-surface` command for route review.

Verify the route surface with:

```bash
flask attack-surface
```

For a clean upgrade from an older local SQLite test database, remove the old local database and reinitialize:

```bash
rm -f instance/forum.db
flask init-db
flask create-admin
```
