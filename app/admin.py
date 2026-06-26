from datetime import datetime

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from sqlalchemy import desc

from . import db_session
from .models import AuditLog, Bookmark, Comment, Post, Report, User
from .security import admin_required, audit_event, clean_text, safe_referrer


bp = Blueprint("admin", __name__, url_prefix="/admin")


def describe_audit_event(log):
    details = _parse_audit_details(log.details)
    event = log.event_type

    if event == "login_success":
        return f"{log.details} signed in."
    if event == "login_failed":
        return f"Failed sign-in attempt for {log.details}."
    if event == "logout":
        return f"{log.details} signed out."
    if event == "account_registered":
        return f"New account registered: {log.details}."
    if event == "email_verified":
        return f"Email verified for {log.details}."
    if event == "password_changed":
        return f"{log.details} changed their password."
    if event == "password_reset_requested":
        return f"Password reset requested for {log.details}."
    if event == "password_reset_completed":
        return f"Password reset completed for {log.details}."
    if event == "session_invalidated":
        return f"{log.details} was signed out because another session became active."
    if event == "post_created":
        return f"Created post #{details.get('post_id', '?')}."
    if event == "post_updated":
        return f"Updated post #{details.get('post_id', '?')}."
    if event == "post_deleted":
        return f"Deleted post #{details.get('post_id', '?')}."
    if event == "post_pin_changed":
        state = "pinned" if details.get("pinned") == "True" else "unpinned"
        return f"Post #{details.get('post_id', '?')} was {state}."
    if event == "post_lock_changed":
        state = "locked" if details.get("locked") == "True" else "unlocked"
        return f"Post #{details.get('post_id', '?')} was {state}."
    if event == "comment_created":
        return f"Added comment #{details.get('comment_id', '?')} to post #{details.get('post_id', '?')}."
    if event == "comment_updated":
        return f"Updated comment #{details.get('comment_id', '?')}."
    if event == "comment_deleted":
        return f"Deleted comment #{details.get('comment_id', '?')}."
    if event == "post_reported":
        return f"Reported post #{details.get('post_id', '?')} as report #{details.get('report_id', '?')}."
    if event == "comment_reported":
        return f"Reported comment #{details.get('comment_id', '?')} as report #{details.get('report_id', '?')}."
    if event == "report_resolved":
        return f"Marked report #{details.get('report_id', '?')} as {details.get('status', 'reviewed')}."
    if event == "role_changed":
        return f"Changed user #{details.get('user_id', '?')} role to {details.get('role', '?')}."
    if event == "account_status_changed":
        state = "active" if details.get("active") == "True" else "inactive"
        return f"Changed user #{details.get('user_id', '?')} account status to {state}."
    if event == "user_verified_by_admin":
        return f"Admin verified user #{details.get('user_id', '?')}."
    if event == "bookmark_added":
        return f"Saved post #{details.get('post_id', '?')}."
    if event == "bookmark_removed":
        return f"Removed saved post #{details.get('post_id', '?')}."
    if event == "account_deactivated":
        return f"{log.details} deactivated their account."
    return log.details or "-"


def _parse_audit_details(raw_details):
    parsed = {}
    for part in (raw_details or "").split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


@bp.route("/")
@admin_required
def dashboard():
    stats = {
        "users": db_session.query(User).count(),
        "active_users": db_session.query(User).filter(User.account_active.is_(True)).count(),
        "unverified_users": db_session.query(User).filter(User.email_verified.is_(False)).count(),
        "posts": db_session.query(Post).filter(Post.is_deleted.is_(False)).count(),
        "comments": db_session.query(Comment).filter(Comment.is_deleted.is_(False)).count(),
        "open_reports": db_session.query(Report).filter(Report.status == "open").count(),
        "locked_posts": db_session.query(Post).filter(Post.is_locked.is_(True), Post.is_deleted.is_(False)).count(),
        "pinned_posts": db_session.query(Post).filter(Post.is_pinned.is_(True), Post.is_deleted.is_(False)).count(),
        "bookmarks": db_session.query(Bookmark).count(),
    }
    recent_logs = db_session.query(AuditLog).order_by(desc(AuditLog.created_at)).limit(20).all()
    actor_ids = {log.actor_user_id for log in recent_logs if log.actor_user_id}
    actors = {}
    if actor_ids:
        actors = {
            user.id: user
            for user in db_session.query(User).filter(User.id.in_(actor_ids)).all()
        }
    audit_descriptions = {
        log.id: describe_audit_event(log)
        for log in recent_logs
    }
    return render_template(
        "admin/dashboard.html",
        stats=stats,
        recent_logs=recent_logs,
        actors=actors,
        audit_descriptions=audit_descriptions,
    )


@bp.route("/users")
@admin_required
def users():
    user_list = db_session.query(User).order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=user_list)


@bp.route("/reports")
@admin_required
def reports():
    status = request.args.get("status", "open")
    query = db_session.query(Report).order_by(desc(Report.created_at))
    if status in {"open", "resolved", "dismissed"}:
        query = query.filter(Report.status == status)
    return render_template("admin/reports.html", reports=query.limit(100).all(), status=status)


@bp.route("/reports/<int:report_id>/resolve", methods=["POST"])
@admin_required
def resolve_report(report_id):
    report = db_session.get(Report, report_id)
    if not report:
        abort(404)
    status = request.form.get("status", "resolved")
    if status not in {"resolved", "dismissed"}:
        abort(400)
    notes, error = clean_text(request.form.get("resolution_notes"), 1000, required=False)
    if error:
        flash(error, "danger")
        return redirect(url_for("admin.reports"))
    report.status = status
    report.resolution_notes = notes
    report.resolved_at = datetime.utcnow()
    db_session.commit()
    audit_event("report_resolved", f"report_id={report.id};status={status}")
    flash("Report updated.", "success")
    return redirect(url_for("admin.reports"))


@bp.route("/users/<int:user_id>/role", methods=["POST"])
@admin_required
def change_role(user_id):
    user = db_session.get(User, user_id)
    if not user:
        abort(404)
    role = request.form.get("role", "user")
    if role not in {"user", "admin"}:
        abort(400)
    if user.role == "admin" and role != "admin":
        active_admins = db_session.query(User).filter(User.role == "admin", User.account_active.is_(True)).count()
        if active_admins <= 1:
            flash("Cannot remove the last active administrator.", "danger")
            return redirect(url_for("admin.users"))
    user.role = role
    db_session.commit()
    audit_event("role_changed", f"user_id={user.id};role={role}")
    flash("Role updated.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/toggle-active", methods=["POST"])
@admin_required
def toggle_active(user_id):
    user = db_session.get(User, user_id)
    if not user:
        abort(404)
    if user.is_admin and user.account_active:
        active_admins = db_session.query(User).filter(User.role == "admin", User.account_active.is_(True)).count()
        if active_admins <= 1:
            flash("Cannot deactivate the last active administrator.", "danger")
            return redirect(url_for("admin.users"))
    user.account_active = not user.account_active
    db_session.commit()
    audit_event("account_status_changed", f"user_id={user.id};active={user.account_active}")
    flash("Account status updated.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/verify", methods=["POST"])
@admin_required
def verify_user(user_id):
    user = db_session.get(User, user_id)
    if not user:
        abort(404)
    user.email_verified = True
    user.email_verification_token_hash = None
    user.email_verification_expires_at = None
    db_session.commit()
    audit_event("user_verified_by_admin", f"user_id={user.id}")
    flash("User email marked verified.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/posts/<int:post_id>/pin", methods=["POST"])
@admin_required
def toggle_pin_post(post_id):
    post = db_session.get(Post, post_id)
    if not post or post.is_deleted:
        abort(404)
    post.is_pinned = not post.is_pinned
    db_session.commit()
    audit_event("post_pin_changed", f"post_id={post.id};pinned={post.is_pinned}")
    flash("Post pin status updated.", "success")
    return redirect(safe_referrer(url_for("forum.post_detail", post_id=post.id)))


@bp.route("/posts/<int:post_id>/lock", methods=["POST"])
@admin_required
def toggle_lock_post(post_id):
    post = db_session.get(Post, post_id)
    if not post or post.is_deleted:
        abort(404)
    post.is_locked = not post.is_locked
    db_session.commit()
    audit_event("post_lock_changed", f"post_id={post.id};locked={post.is_locked}")
    flash("Post lock status updated.", "success")
    return redirect(safe_referrer(url_for("forum.post_detail", post_id=post.id)))
