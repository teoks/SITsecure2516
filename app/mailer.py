import smtplib
import ssl
from email.message import EmailMessage

from flask import current_app, url_for


def build_external_url(endpoint, **values):
    """Build a public URL from APP_BASE_URL instead of the internal Gunicorn host."""
    relative = url_for(endpoint, **values)
    return f"{current_app.config['APP_BASE_URL'].rstrip('/')}{relative}"


def send_email(to_email, subject, body):
    """Send a plain-text SMTP email using STARTTLS or SMTP_SSL."""
    if not current_app.config.get("MAIL_ENABLED"):
        current_app.logger.info("mail_disabled subject=%s to=%s", subject, to_email)
        return False

    server = current_app.config.get("MAIL_SERVER")
    if not server:
        raise RuntimeError("MAIL_SERVER is not configured")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = current_app.config.get("MAIL_DEFAULT_SENDER")
    message["To"] = to_email
    message.set_content(body)

    port = current_app.config.get("MAIL_PORT", 587)
    username = current_app.config.get("MAIL_USERNAME")
    password = current_app.config.get("MAIL_PASSWORD")
    use_tls = current_app.config.get("MAIL_USE_TLS")
    use_ssl = current_app.config.get("MAIL_USE_SSL")
    context = ssl.create_default_context()

    if use_ssl:
        with smtplib.SMTP_SSL(server, port, context=context, timeout=20) as smtp:
            if username:
                smtp.login(username, password)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(server, port, timeout=20) as smtp:
            smtp.ehlo()
            if use_tls:
                smtp.starttls(context=context)
                smtp.ehlo()
            if username:
                smtp.login(username, password)
            smtp.send_message(message)

    current_app.logger.info("mail_sent subject=%s to=%s", subject, to_email)
    return True


def send_verification_email(user, token):
    verify_url = build_external_url("auth.verify_email", token=token)
    body = f"""Hello {user.username},

Please verify your Secure Student Forum account by opening this link:
{verify_url}

The link is time-limited. If you did not create this account, you can ignore this email.

Regards,
Secure Student Forum
"""
    return send_email(user.email, "Verify your Secure Student Forum account", body)


def send_password_reset_email(user, token):
    reset_url = build_external_url("auth.reset_password", token=token)
    body = f"""Hello {user.username},

A password reset was requested for your Secure Student Forum account.
Open this link to set a new password:
{reset_url}

The link is time-limited. If you did not request this reset, you can ignore this email.

Regards,
Secure Student Forum
"""
    return send_email(user.email, "Reset your Secure Student Forum password", body)
