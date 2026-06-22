from datetime import datetime

from flask_login import UserMixin
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utcnow():
    return datetime.utcnow()


class User(UserMixin, Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(32), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="user")
    account_active = Column(Boolean, nullable=False, default=True)
    email_verified = Column(Boolean, nullable=False, default=False)
    email_verification_token_hash = Column(String(128), nullable=True, index=True)
    email_verification_expires_at = Column(DateTime, nullable=True)
    password_reset_token_hash = Column(String(128), nullable=True, index=True)
    password_reset_expires_at = Column(DateTime, nullable=True)
    failed_login_count = Column(Integer, nullable=False, default=0)
    lock_until = Column(DateTime, nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    active_session_token_hash = Column(String(128), nullable=True)
    active_session_started_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    posts = relationship("Post", back_populates="author", cascade="save-update")
    comments = relationship("Comment", back_populates="author", cascade="save-update")
    reports = relationship("Report", back_populates="reporter", cascade="save-update")
    bookmarks = relationship("Bookmark", back_populates="user", cascade="save-update")

    @property
    def is_active(self):
        return bool(self.account_active)

    @property
    def is_admin(self):
        return self.role == "admin"

    def __repr__(self):
        return f"<User {self.username}>"


class Post(Base):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    title = Column(String(120), nullable=False)
    category = Column(String(50), nullable=False, default="General")
    body = Column(Text, nullable=False)
    is_deleted = Column(Boolean, nullable=False, default=False)
    is_pinned = Column(Boolean, nullable=False, default=False, index=True)
    is_locked = Column(Boolean, nullable=False, default=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    deleted_at = Column(DateTime, nullable=True)

    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="post", cascade="save-update")
    reports = relationship("Report", back_populates="post", cascade="save-update")
    bookmarks = relationship("Bookmark", back_populates="post", cascade="save-update")

    def __repr__(self):
        return f"<Post {self.title[:20]}>"


class Comment(Base):
    __tablename__ = "comments"

    id = Column(Integer, primary_key=True)
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    body = Column(Text, nullable=False)
    is_deleted = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    deleted_at = Column(DateTime, nullable=True)

    post = relationship("Post", back_populates="comments")
    author = relationship("User", back_populates="comments")
    reports = relationship("Report", back_populates="comment", cascade="save-update")

    def __repr__(self):
        return f"<Comment {self.id}>"


class Bookmark(Base):
    __tablename__ = "bookmarks"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)

    user = relationship("User", back_populates="bookmarks")
    post = relationship("Post", back_populates="bookmarks")

    def __repr__(self):
        return f"<Bookmark user={self.user_id} post={self.post_id}>"


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    reporter_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=True, index=True)
    comment_id = Column(Integer, ForeignKey("comments.id"), nullable=True, index=True)
    reason = Column(String(80), nullable=False)
    details = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default="open", index=True)
    resolution_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    resolved_at = Column(DateTime, nullable=True)

    reporter = relationship("User", back_populates="reports")
    post = relationship("Post", back_populates="reports")
    comment = relationship("Comment", back_populates="reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    actor_user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    event_type = Column(String(80), nullable=False)
    details = Column(Text, nullable=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)
    previous_hash = Column(String(64), nullable=True)
    entry_hash = Column(String(64), nullable=True, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
