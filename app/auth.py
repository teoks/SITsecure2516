from datetime import datetime, timedelta

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func, or_
from werkzeug.security import check_password_hash, generate_password_hash

from . import db_session
from .models import User
from .mailer import send_password_reset_email, send_verification_email
from .security import (
    DUMMY_PASSWORD_HASH,
    audit_event,
    create_token_pair,
    hash_token,
    is_safe_redirect_target,
    normalize_email,
    normalize_username,
    record_failed_login,
    clear_user_session,
    reset_login_failures,
    rotate_user_session,
    user_is_locked,
    validate_email,
    validate_password,
    validate_username,
)

bp = Blueprint("auth", __name__)


def _set_verification_token(user):
    token, token_hash = create_token_pair()
    user.email_verification_token_hash = token_hash
    user.email_verification_expires_at = datetime.utcnow() + timedelta(minutes=current_app.config.get("EMAIL_TOKEN_MINUTES", 60))
    return token


def _set_reset_token(user):
    token, token_hash = create_token_pair()
    user.password_reset_token_hash = token_hash
    user.password_reset_expires_at = datetime.utcnow() + timedelta(minutes=current_app.config.get("PASSWORD_RESET_MINUTES", 30))
    return token


def _flash_dev_link(message, endpoint, token):
    if current_app.config.get("DEV_SHOW_TOKENS"):
        link = url_for(endpoint, token=token, _external=False)
        flash(f"{message} Local test link: {link}", "info")
    else:
        flash(message, "info")


def rate_limit(limit):
    from .security import limiter
    def decorator(func):
        if limiter:
            return limiter.limit(limit)(func)
        return func
    return decorator


@bp.route("/register", methods=["GET", "POST"])
@rate_limit("3 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("forum.index"))

    if request.method == "POST":
        username = normalize_username(request.form.get("username"))
        email = normalize_email(request.form.get("email"))
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        errors = []
        if not validate_username(username):
            errors.append("Username must be 3-32 characters and may contain letters, numbers, dot, underscore, or hyphen.")
        if not validate_email(email):
            errors.append("Enter a valid email address.")
        if password != confirm:
            errors.append("Passwords do not match.")
        errors.extend(validate_password(password, username=username, email=email))
        existing = db_session.query(User).filter((User.username == username) | (User.email == email)).first()
        if existing:
            errors.append("Username or email is already registered.")

        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("auth/register.html", form=request.form), 400

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password, method="scrypt"),
            role="user",
            account_active=True,
            email_verified=not current_app.config.get("EMAIL_VERIFICATION_REQUIRED"),
        )
        token = _set_verification_token(user) if not user.email_verified else None
        db_session.add(user)
        db_session.commit()
        audit_event("account_registered", username)
        if token:
            if current_app.config.get("MAIL_ENABLED"):
                try:
                    send_verification_email(user, token)
                    flash("Registration successful. Please check your email to verify your account.", "success")
                except Exception:
                    current_app.logger.exception("Failed to send verification email")
                    flash("Account created, but the verification email could not be sent. Please contact an administrator.", "danger")
            else:
                _flash_dev_link("Registration successful. Verify your email before posting.", "auth.verify_email", token)
        else:
            flash("Registration successful. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form={})


@bp.route("/verify-email/<token>")
def verify_email(token):
    token_hash = hash_token(token)
    user = db_session.query(User).filter(User.email_verification_token_hash == token_hash).first()
    if not user or not user.email_verification_expires_at or user.email_verification_expires_at < datetime.utcnow():
        flash("Verification link is invalid or expired.", "danger")
        return redirect(url_for("auth.login"))
    user.email_verified = True
    user.email_verification_token_hash = None
    user.email_verification_expires_at = None
    db_session.commit()
    audit_event("email_verified", user.username)
    flash("Email verified. You can now create posts and comments.", "success")
    return redirect(url_for("auth.login"))


@bp.route("/resend-verification", methods=["POST"])
@login_required
def resend_verification():
    if current_user.email_verified:
        flash("Your email is already verified.", "info")
        return redirect(url_for("auth.profile"))
    token = _set_verification_token(current_user)
    db_session.commit()
    audit_event("verification_resent", current_user.username)
    if current_app.config.get("MAIL_ENABLED"):
        try:
            send_verification_email(current_user, token)
            flash("A new verification email has been sent.", "success")
        except Exception:
            current_app.logger.exception("Failed to resend verification email")
            flash("Verification email could not be sent. Please try again later.", "danger")
    else:
        _flash_dev_link("A new verification link has been generated.", "auth.verify_email", token)
    return redirect(url_for("auth.profile"))


@bp.route("/login", methods=["GET", "POST"])
@rate_limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("forum.index"))

    if request.method == "POST":
        identifier = normalize_email(request.form.get("identifier"))
        password = request.form.get("password", "")
        user = db_session.query(User).filter(
            or_(func.lower(User.username) == identifier, func.lower(User.email) == identifier)
        ).first()

        if user and user_is_locked(user):
            flash("Too many failed attempts. Please try again later.", "danger")
            audit_event("login_blocked", identifier)
            return render_template("auth/login.html", identifier=identifier), 429

        valid = bool(user and user.account_active and check_password_hash(user.password_hash, password))
        if not valid:
            if user:
                record_failed_login(user)
            else:
                check_password_hash(DUMMY_PASSWORD_HASH, password or "")
            flash("We could not sign you in with those details.", "danger")
            audit_event("login_failed", identifier)
            return render_template("auth/login.html", identifier=identifier), 401

        reset_login_failures(user)
        session.permanent = True
        login_user(user)
        rotate_user_session(user)
        audit_event("login_success", user.username)
        next_url = request.args.get("next")
        if is_safe_redirect_target(next_url):
            return redirect(next_url)
        return redirect(url_for("forum.index"))

    return render_template("auth/login.html", identifier="")


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    username = current_user.username
    clear_user_session(current_user)
    logout_user()
    session.clear()
    audit_event("logout", username)
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/profile")
@login_required
def profile():
    return render_template("auth/profile.html")


@bp.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        email = normalize_email(request.form.get("email"))
        if not validate_email(email):
            flash("Enter a valid email address.", "danger")
            return render_template("auth/edit_profile.html"), 400
        existing = db_session.query(User).filter(User.email == email, User.id != current_user.id).first()
        if existing:
            flash("Email address is already in use.", "danger")
            return render_template("auth/edit_profile.html"), 400
        if email != current_user.email:
            current_user.email = email
            current_user.email_verified = False
            token = _set_verification_token(current_user)
            if current_app.config.get("MAIL_ENABLED"):
                try:
                    send_verification_email(current_user, token)
                    flash("Email updated. Please check your new email address for verification.", "success")
                except Exception:
                    current_app.logger.exception("Failed to send profile verification email")
                    flash("Email updated, but the verification email could not be sent. Please contact an administrator.", "danger")
            else:
                _flash_dev_link("Email updated. Verify the new address.", "auth.verify_email", token)
        db_session.commit()
        audit_event("profile_updated", current_user.username)
        flash("Profile updated.", "success")
        return redirect(url_for("auth.profile"))
    return render_template("auth/edit_profile.html")


@bp.route("/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        errors = []
        if not check_password_hash(current_user.password_hash, current_password):
            errors.append("Current password is incorrect.")
        if new_password != confirm:
            errors.append("New passwords do not match.")
        errors.extend(validate_password(new_password, username=current_user.username, email=current_user.email))
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("auth/change_password.html"), 400
        current_user.password_hash = generate_password_hash(new_password, method="scrypt")
        current_user.password_reset_token_hash = None
        current_user.password_reset_expires_at = None
        rotate_user_session(current_user)
        db_session.commit()
        audit_event("password_changed", current_user.username)
        flash("Password changed. Please use the new password next time you log in.", "success")
        return redirect(url_for("auth.profile"))
    return render_template("auth/change_password.html")


@bp.route("/password/forgot", methods=["GET", "POST"])
@rate_limit("3 per minute")
def forgot_password():
    if request.method == "POST":
        email = normalize_email(request.form.get("email"))
        user = db_session.query(User).filter(func.lower(User.email) == email).first()
        if user and user.account_active:
            token = _set_reset_token(user)
            db_session.commit()
            audit_event("password_reset_requested", email)
            if current_app.config.get("MAIL_ENABLED"):
                try:
                    send_password_reset_email(user, token)
                except Exception:
                    current_app.logger.exception("Failed to send password reset email")
            else:
                _flash_dev_link("If the email exists, a reset link has been generated.", "auth.reset_password", token)
        else:
            check_password_hash(DUMMY_PASSWORD_HASH, "dummy")
        flash("If the email exists, a reset link has been generated.", "info")
        return redirect(url_for("auth.login"))
    return render_template("auth/forgot_password.html")


@bp.route("/password/reset/<token>", methods=["GET", "POST"])
@rate_limit("5 per minute")
def reset_password(token):
    token_hash = hash_token(token)
    user = db_session.query(User).filter(User.password_reset_token_hash == token_hash).first()
    if not user or not user.password_reset_expires_at or user.password_reset_expires_at < datetime.utcnow():
        flash("Password reset link is invalid or expired.", "danger")
        return redirect(url_for("auth.forgot_password"))
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        errors = []
        if password != confirm:
            errors.append("Passwords do not match.")
        errors.extend(validate_password(password, username=user.username, email=user.email))
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("auth/reset_password.html"), 400
        user.password_hash = generate_password_hash(password, method="scrypt")
        user.password_reset_token_hash = None
        user.password_reset_expires_at = None
        user.failed_login_count = 0
        user.lock_until = None
        user.active_session_token_hash = None
        user.active_session_started_at = None
        db_session.commit()
        audit_event("password_reset_completed", user.username)
        flash("Password reset complete. Please log in.", "success")
        return redirect(url_for("auth.login"))
    return render_template("auth/reset_password.html")


@bp.route("/account/delete", methods=["POST"])
@login_required
def delete_account():
    password = request.form.get("password", "")
    if not check_password_hash(current_user.password_hash, password):
        flash("Password confirmation failed.", "danger")
        return redirect(url_for("auth.profile"))
    if current_user.is_admin:
        active_admins = db_session.query(User).filter(User.role == "admin", User.account_active.is_(True)).count()
        if active_admins <= 1:
            flash("The last active administrator account cannot be deactivated.", "danger")
            return redirect(url_for("auth.profile"))
    username = current_user.username
    current_user.account_active = False
    clear_user_session(current_user)
    db_session.commit()
    logout_user()
    session.clear()
    audit_event("account_deactivated", username)
    flash("Your account has been deactivated.", "info")
    return redirect(url_for("auth.login"))
