from datetime import datetime

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import or_

from . import db_session
from .models import Bookmark, Comment, Post, Report
from .security import audit_event, clean_text, owner_or_admin, verified_required

bp = Blueprint("forum", __name__)

ALLOWED_CATEGORIES = (
    "General",
    "Cybersecurity",
    "Programming",
    "Database",
    "Networking",
    "Project Help",
    "Announcements",
)


def get_post_or_404(post_id, include_deleted=False):
    post = db_session.get(Post, post_id)
    if not post or (post.is_deleted and not include_deleted):
        abort(404)
    return post


def get_comment_or_404(comment_id, include_deleted=False):
    comment = db_session.get(Comment, comment_id)
    if not comment or (comment.is_deleted and not include_deleted):
        abort(404)
    return comment


def normalize_category(value):
    value = (value or "General").strip()
    return value if value in ALLOWED_CATEGORIES else "General"


def rate_limit(limit):
    from .security import limiter
    def decorator(func):
        if limiter:
            return limiter.limit(limit)(func)
        return func
    return decorator


@bp.route("/")
def index():
    search, error = clean_text(request.args.get("q", ""), 80, required=False)
    category = request.args.get("category", "").strip()
    sort = request.args.get("sort", "latest").strip()
    if sort not in {"latest", "oldest"}:
        sort = "latest"
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1
    per_page = 10
    if error:
        search = ""
        flash(error, "warning")
    query = db_session.query(Post).filter(Post.is_deleted.is_(False))
    if category in ALLOWED_CATEGORIES:
        query = query.filter(Post.category == category)
    if search:
        pattern = f"%{search}%"
        query = query.filter(or_(Post.title.ilike(pattern), Post.body.ilike(pattern), Post.category.ilike(pattern)))
    if sort == "oldest":
        query = query.order_by(Post.created_at.asc())
    else:
        query = query.order_by(Post.is_pinned.desc(), Post.created_at.desc())
    total_posts = query.count()
    total_pages = max(1, (total_posts + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages
    posts = query.offset((page - 1) * per_page).limit(per_page).all()
    category_posts = db_session.query(Post).filter(
        Post.is_deleted.is_(False),
        Post.category.in_(ALLOWED_CATEGORIES),
    ).order_by(Post.is_pinned.desc(), Post.created_at.desc()).all()
    category_counts = {category: 0 for category in ALLOWED_CATEGORIES}
    latest_posts_by_category = {}
    for category_post in category_posts:
        category_counts[category_post.category] += 1
        latest_posts_by_category.setdefault(category_post.category, category_post)
    bookmarked_post_ids = set()
    if current_user.is_authenticated:
        bookmarked_post_ids = {
            row.post_id for row in db_session.query(Bookmark.post_id).filter(Bookmark.user_id == current_user.id).all()
        }
    return render_template(
        "forum/index.html",
        posts=posts,
        search=search or "",
        categories=ALLOWED_CATEGORIES,
        selected_category=category,
        selected_sort=sort,
        category_counts=category_counts,
        latest_posts_by_category=latest_posts_by_category,
        page=page,
        per_page=per_page,
        total_posts=total_posts,
        total_pages=total_pages,
        bookmarked_post_ids=bookmarked_post_ids,
    )


@bp.route("/saved")
@verified_required
def saved_posts():
    bookmarks = db_session.query(Bookmark).join(Post).filter(
        Bookmark.user_id == current_user.id,
        Post.is_deleted.is_(False),
    ).order_by(Bookmark.created_at.desc()).limit(100).all()
    return render_template("forum/saved_posts.html", bookmarks=bookmarks)


@bp.route("/posts/new", methods=["GET", "POST"])
@verified_required
@rate_limit("10 per hour")
def create_post():
    if request.method == "POST":
        title, title_error = clean_text(request.form.get("title"), 120)
        category = normalize_category(request.form.get("category"))
        body, body_error = clean_text(request.form.get("body"), 5000)
        errors = [e for e in (title_error, body_error) if e]
        if title and len(title) < 3:
            errors.append("Title must be at least 3 characters long.")
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("forum/post_form.html", mode="Create", post=request.form, categories=ALLOWED_CATEGORIES), 400
        post = Post(title=title, category=category, body=body, user_id=current_user.id)
        db_session.add(post)
        db_session.commit()
        audit_event("post_created", f"post_id={post.id}")
        flash("Post created.", "success")
        return redirect(url_for("forum.post_detail", post_id=post.id))
    return render_template("forum/post_form.html", mode="Create", post={"category": "General"}, categories=ALLOWED_CATEGORIES)


@bp.route("/posts/<int:post_id>")
def post_detail(post_id):
    post = get_post_or_404(post_id)
    comments = db_session.query(Comment).filter(
        Comment.post_id == post.id,
        Comment.is_deleted.is_(False),
    ).order_by(Comment.created_at.asc()).all()
    is_bookmarked = False
    if current_user.is_authenticated:
        is_bookmarked = db_session.query(Bookmark).filter(Bookmark.user_id == current_user.id, Bookmark.post_id == post.id).first() is not None
    return render_template("forum/post_detail.html", post=post, comments=comments, is_bookmarked=is_bookmarked)


@bp.route("/posts/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    post = get_post_or_404(post_id)
    if post.is_locked and not current_user.is_admin:
        abort(403)
    if not owner_or_admin(post.user_id):
        abort(403)
    if request.method == "POST":
        title, title_error = clean_text(request.form.get("title"), 120)
        category = normalize_category(request.form.get("category"))
        body, body_error = clean_text(request.form.get("body"), 5000)
        errors = [e for e in (title_error, body_error) if e]
        if title and len(title) < 3:
            errors.append("Title must be at least 3 characters long.")
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("forum/post_form.html", mode="Edit", post=post, categories=ALLOWED_CATEGORIES), 400
        post.title = title
        post.category = category
        post.body = body
        db_session.commit()
        audit_event("post_updated", f"post_id={post.id}")
        flash("Post updated.", "success")
        return redirect(url_for("forum.post_detail", post_id=post.id))
    return render_template("forum/post_form.html", mode="Edit", post=post, categories=ALLOWED_CATEGORIES)


@bp.route("/posts/<int:post_id>/delete", methods=["POST"])
@login_required
def delete_post(post_id):
    post = get_post_or_404(post_id)
    if not owner_or_admin(post.user_id):
        abort(403)
    post.is_deleted = True
    post.deleted_at = datetime.utcnow()
    db_session.commit()
    audit_event("post_deleted", f"post_id={post.id}")
    flash("Post deleted.", "info")
    return redirect(url_for("forum.index"))


@bp.route("/posts/<int:post_id>/bookmark", methods=["POST"])
@verified_required
@rate_limit("30 per hour")
def toggle_bookmark(post_id):
    post = get_post_or_404(post_id)
    bookmark = db_session.query(Bookmark).filter(Bookmark.user_id == current_user.id, Bookmark.post_id == post.id).first()
    if bookmark:
        db_session.delete(bookmark)
        event = "bookmark_removed"
        flash("Post removed from saved posts.", "info")
    else:
        db_session.add(Bookmark(user_id=current_user.id, post_id=post.id))
        event = "bookmark_added"
        flash("Post saved.", "success")
    db_session.commit()
    audit_event(event, f"post_id={post.id}")
    return redirect(request.referrer if request.referrer else url_for("forum.post_detail", post_id=post.id))


@bp.route("/posts/<int:post_id>/comments", methods=["POST"])
@verified_required
@rate_limit("30 per hour")
def add_comment(post_id):
    post = get_post_or_404(post_id)
    if post.is_locked and not current_user.is_admin:
        abort(403)
    body, body_error = clean_text(request.form.get("body"), 1000)
    if body_error:
        flash(body_error, "danger")
        return redirect(url_for("forum.post_detail", post_id=post.id))
    comment = Comment(post_id=post.id, user_id=current_user.id, body=body)
    db_session.add(comment)
    db_session.commit()
    audit_event("comment_created", f"comment_id={comment.id};post_id={post.id}")
    flash("Comment added.", "success")
    return redirect(url_for("forum.post_detail", post_id=post.id))


@bp.route("/comments/<int:comment_id>/edit", methods=["GET", "POST"])
@login_required
def edit_comment(comment_id):
    comment = get_comment_or_404(comment_id)
    if comment.post.is_locked and not current_user.is_admin:
        abort(403)
    if not owner_or_admin(comment.user_id):
        abort(403)
    if request.method == "POST":
        body, body_error = clean_text(request.form.get("body"), 1000)
        if body_error:
            flash(body_error, "danger")
            return render_template("forum/comment_form.html", comment=comment), 400
        comment.body = body
        db_session.commit()
        audit_event("comment_updated", f"comment_id={comment.id}")
        flash("Comment updated.", "success")
        return redirect(url_for("forum.post_detail", post_id=comment.post_id))
    return render_template("forum/comment_form.html", comment=comment)


@bp.route("/comments/<int:comment_id>/delete", methods=["POST"])
@login_required
def delete_comment(comment_id):
    comment = get_comment_or_404(comment_id)
    if not owner_or_admin(comment.user_id):
        abort(403)
    comment.is_deleted = True
    comment.deleted_at = datetime.utcnow()
    db_session.commit()
    audit_event("comment_deleted", f"comment_id={comment.id}")
    flash("Comment deleted.", "info")
    return redirect(url_for("forum.post_detail", post_id=comment.post_id))


@bp.route("/posts/<int:post_id>/report", methods=["GET", "POST"])
@verified_required
@rate_limit("10 per hour")
def report_post(post_id):
    post = get_post_or_404(post_id)
    if request.method == "POST":
        reason, reason_error = clean_text(request.form.get("reason"), 80)
        details, details_error = clean_text(request.form.get("details"), 1000, required=False)
        if reason_error or details_error:
            flash(reason_error or details_error, "danger")
            return render_template("forum/report_form.html", target="post", post=post), 400
        report = Report(reporter_user_id=current_user.id, post_id=post.id, reason=reason, details=details)
        db_session.add(report)
        db_session.commit()
        audit_event("post_reported", f"post_id={post.id};report_id={report.id}")
        flash("Report submitted for moderator review.", "success")
        return redirect(url_for("forum.post_detail", post_id=post.id))
    return render_template("forum/report_form.html", target="post", post=post)


@bp.route("/comments/<int:comment_id>/report", methods=["GET", "POST"])
@verified_required
@rate_limit("10 per hour")
def report_comment(comment_id):
    comment = get_comment_or_404(comment_id)
    if request.method == "POST":
        reason, reason_error = clean_text(request.form.get("reason"), 80)
        details, details_error = clean_text(request.form.get("details"), 1000, required=False)
        if reason_error or details_error:
            flash(reason_error or details_error, "danger")
            return render_template("forum/report_form.html", target="comment", comment=comment), 400
        report = Report(reporter_user_id=current_user.id, comment_id=comment.id, reason=reason, details=details)
        db_session.add(report)
        db_session.commit()
        audit_event("comment_reported", f"comment_id={comment.id};report_id={report.id}")
        flash("Report submitted for moderator review.", "success")
        return redirect(url_for("forum.post_detail", post_id=comment.post_id))
    return render_template("forum/report_form.html", target="comment", comment=comment)
