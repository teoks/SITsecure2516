import argparse
import datetime as dt
import random

from sqlalchemy import or_
from werkzeug.security import generate_password_hash

from app import create_app, db_session
from app.models import Base, Bookmark, Comment, Post, Report, User


DEFAULT_PASSWORD = "P@ssw0rd12345"
DEFAULT_POST_COUNT = 200
SEED = 2516
OLD_SEED_EMAIL_DOMAIN = "seed.local"
SEED_EMAIL_DOMAIN = "sitforum.local"
OLD_SEED_TITLE_PREFIX = "[Seed]"

POST_DISTRIBUTION = {
    "Cybersecurity": 45,
    "Programming": 40,
    "Project Help": 35,
    "Networking": 30,
    "Database": 25,
    "General": 15,
    "Announcements": 10,
}

SEEDED_USERS = [
    ("admin1", "admin1@sitforum.local", "admin", True),
    ("primary_admin", "primary_admin@sitforum.local", "admin", True),
    ("security_admin", "security_admin@sitforum.local", "admin", True),
    ("moderator_admin", "moderator_admin@sitforum.local", "admin", True),
    ("verified_alice", "verified_alice@sitforum.local", "user", True),
    ("verified_bob", "verified_bob@sitforum.local", "user", True),
    ("verified_charlie", "verified_charlie@sitforum.local", "user", True),
    ("verified_david", "verified_david@sitforum.local", "user", True),
    ("verified_hannah", "verified_hannah@sitforum.local", "user", True),
    ("verified_isaac", "verified_isaac@sitforum.local", "user", True),
    ("verified_jasmine", "verified_jasmine@sitforum.local", "user", True),
    ("verified_kevin", "verified_kevin@sitforum.local", "user", True),
    ("verified_lina", "verified_lina@sitforum.local", "user", True),
    ("verified_marcus", "verified_marcus@sitforum.local", "user", True),
    ("verified_nora", "verified_nora@sitforum.local", "user", True),
    ("unverified_emma", "unverified_emma@sitforum.local", "user", False),
    ("unverified_frank", "unverified_frank@sitforum.local", "user", False),
    ("unverified_grace", "unverified_grace@sitforum.local", "user", False),
]

LEGACY_SEEDED_USERNAMES = {
    "admin1",
    "primary_admin",
    "security_admin",
    "moderator_admin",
    "verified_alice",
    "verified_bob",
    "verified_charlie",
    "verified_david",
    "unverified_emma",
    "unverified_frank",
    "unverified_grace",
}

LEGACY_SEEDED_POST_TITLES = {
    "Understanding SQL Injection Risks",
    "Python Virtual Environment Best Practices",
    "Difference Between Layer 2 and Layer 3 Switches",
    "AWS EC2 Security Group Confusion",
    "Ubuntu Service Management With systemd",
    "SQLite vs PostgreSQL",
    "How Does CSRF Protection Work?",
    "Bootstrap vs Tailwind CSS",
    "Nginx Reverse Proxy Benefits",
    "Linux File Permission Breakdown",
    "Flask Blueprint Organization",
    "Password Hashing Recommendations",
    "Static IP vs Dynamic IP",
    "Common Causes of Packet Loss",
    "Why Use Gunicorn With Flask",
    "Understanding Content Security Policy",
    "Using journalctl Effectively",
    "Responsive Design Challenges",
    "Database Backup Strategies",
    "What Happens During Boot Process",
    "Forum Rules and Posting Guidelines",
    "Scheduled Maintenance Window",
    "Password Reset Policy Reminder",
    "Security Awareness Week Discussion Threads",
    "Need Ideas for Secure Forum Project Features",
    "How to Explain Threat Modelling in Presentation",
    "Database ERD Review for Coursework",
    "Testing Checklist Before Submission",
    "Deployment Report Screenshots",
}

TOPICS = {
    "Cybersecurity": [
        ("SQL injection prevention checklist", "How should we validate input, parameterize queries, and test database forms?"),
        ("CSRF token debugging", "What is the best way to confirm every state-changing form is protected?"),
        ("Password hashing choices", "Should our report compare scrypt, bcrypt, and plain SHA256 with examples?"),
        ("Account lockout testing", "How can we prove brute-force protection works without locking everyone out?"),
        ("Content Security Policy review", "What CSP rules are realistic for a Flask coursework application?"),
        ("Session cookie security", "Which cookie settings matter most behind HTTPS and a reverse proxy?"),
        ("Audit log tamper resistance", "How do hash chains help detect changed moderation records?"),
        ("Least privilege deployment", "Which Linux permissions should protect the app folder and environment file?"),
        ("Secure password reset flow", "What should expire, what should be logged, and what should never be displayed?"),
        ("Rate limiting login attempts", "How do we explain rate limits clearly in the security section?"),
    ],
    "Programming": [
        ("Flask blueprint structure", "Is it better to split auth, forum, and admin routes into separate modules?"),
        ("SQLAlchemy relationship design", "How should users, posts, comments, bookmarks, and reports connect?"),
        ("Form validation strategy", "Where should length checks, category checks, and text cleanup happen?"),
        ("Testing Flask routes", "Which routes should have smoke tests before the final submission?"),
        ("Virtual environment workflow", "Should every teammate recreate the same venv from requirements.txt?"),
        ("Error page handling", "How do we make 403, 404, and 413 errors look consistent?"),
        ("Template reuse in Jinja", "What belongs in base.html versus individual page templates?"),
        ("Pagination approach", "Would limit-based loading be enough for a student forum demo?"),
        ("CLI commands for admin tasks", "Should init-db, create-admin, and backup-db stay as Flask CLI commands?"),
        ("Code organization for helpers", "Where should validation, audit logging, and security decorators live?"),
    ],
    "Project Help": [
        ("Threat model slide review", "Can someone check whether our assets, attackers, and mitigations are clear?"),
        ("ERD feedback request", "Does our diagram need separate tables for reports and bookmarks?"),
        ("Deployment screenshot checklist", "Which screenshots best prove service status, HTTPS, and reverse proxy setup?"),
        ("Security report wording", "How detailed should the vulnerability mitigation explanations be?"),
        ("Demo flow planning", "What should we click through first during the final presentation?"),
        ("Test case table ideas", "How should we document expected results for login, posting, and moderation?"),
        ("Admin dashboard justification", "What should we say about moderation features and accountability?"),
        ("Backup and recovery section", "How can we explain database backups without overcomplicating the report?"),
        ("Peer review before submission", "Can someone review our README and deployment notes?"),
        ("Final checklist for SIT submission", "What files and screenshots should be ready before upload?"),
    ],
    "Networking": [
        ("Nginx reverse proxy purpose", "Why should Flask stay behind Gunicorn and Nginx instead of public exposure?"),
        ("Security group rules", "Which ports should be public, and which should stay internal only?"),
        ("HTTPS certificate renewal", "How do we explain certificate renewal and TLS in the deployment section?"),
        ("Private Gunicorn socket", "What is the benefit of binding Gunicorn to a Unix socket?"),
        ("Firewall rule verification", "Which commands prove the server exposes only required services?"),
        ("DNS and Elastic IP notes", "Should we use DNS names or direct IP addresses in screenshots?"),
        ("Reverse proxy headers", "Which forwarded headers matter when Flask is behind Nginx?"),
        ("Port 8000 exposure risk", "Why is exposing the application server port a bad practice?"),
        ("Internal health checks", "How can we test the app locally on the EC2 host before checking HTTPS?"),
        ("Network troubleshooting steps", "What should we inspect if Nginx returns a gateway error?"),
    ],
    "Database": [
        ("SQLite limitations", "When is SQLite acceptable for coursework, and when would PostgreSQL be better?"),
        ("Database backup strategy", "How often should backups run, and where should they be stored?"),
        ("Schema initialization", "What is the safest way to recreate missing tables during setup?"),
        ("Foreign key relationships", "How should comments, reports, and bookmarks reference posts and users?"),
        ("Soft delete design", "Why keep deleted posts and comments instead of removing rows immediately?"),
        ("Indexing forum queries", "Which columns are worth indexing for category filters and moderation pages?"),
        ("Seed data generation", "How can we create realistic demo data without touching real user records?"),
        ("Audit log storage", "Should audit records be editable, and how do we detect tampering?"),
        ("Migration planning", "At what point should a Flask app move from create_all to migrations?"),
        ("Database file permissions", "Who should own the SQLite database file on the EC2 server?"),
    ],
    "General": [
        ("Study group planning", "Who wants to form a revision group for the secure software assignment?"),
        ("Useful debugging habits", "What logs do you check first when a Flask page returns an error?"),
        ("Presentation timing tips", "How do you keep a technical demo within the time limit?"),
        ("Documentation style", "Should README files be short and practical or detailed like a setup guide?"),
        ("Coursework reflection", "What was the hardest part of building a secure forum from scratch?"),
        ("Team workflow notes", "How do teams divide frontend, backend, deployment, and testing tasks fairly?"),
        ("Local development setup", "What should be documented so another student can run the app easily?"),
        ("Troubleshooting checklist", "Which simple checks save the most time before asking for help?"),
    ],
}

TITLE_CONTEXTS = [
    "for coursework teams",
    "in the Flask forum project",
    "before final submission",
    "for the deployment demo",
    "during security review",
    "with practical examples",
]

ANNOUNCEMENTS = [
    ("Forum Rules and Posting Guidelines", "Keep discussions respectful, academic, and relevant to coursework. Do not share passwords, private keys, or assessment answers.", True, True),
    ("Scheduled Maintenance Window", "The forum may be unavailable during the weekly maintenance window while updates and backups are verified.", True, True),
    ("Password Reset Policy Reminder", "Use strong unique passwords and request a reset if you suspect your account has been exposed.", True, False),
    ("Security Awareness Week Discussion Threads", "New discussion threads will open this week for phishing, secure coding, database security, and incident response topics.", False, False),
    ("Project Submission Support Thread", "Use this thread to ask about deployment evidence, screenshots, and final documentation checks.", True, False),
    ("Moderation Queue Review Notice", "Administrators will review open reports daily during the final project period.", False, False),
    ("Database Backup Verification Reminder", "Teams should verify that backups can be created and restored before the final demonstration.", False, True),
    ("HTTPS Configuration Check", "Please confirm your deployment redirects HTTP traffic to HTTPS before collecting final evidence.", False, False),
    ("Account Verification Reminder", "Only verified users can create posts and comments, so complete email verification before demo day.", False, False),
    ("Final Demo Day Expectations", "Prepare a short walkthrough covering registration, login, posting, reporting, admin review, and deployment controls.", True, True),
]

COMMENT_BODIES = [
    "This helped clarify the issue for our team.",
    "We handled this by documenting the risk and then showing the mitigation in the demo.",
    "A short screenshot with a clear caption would make this easier to explain.",
    "Check the logs as well, because they usually show the real failure before the browser does.",
    "I would include both the technical control and the reason it matters.",
    "This is also useful for the testing section of the report.",
    "Our group used a checklist so we did not miss the small configuration details.",
    "Good point. It may be worth linking this to the threat model.",
]

REPORT_REASONS = [
    "Spam or duplicate content",
    "Possible sensitive information",
    "Off-topic discussion",
    "Inappropriate wording",
    "Needs moderator review",
]


def parse_args():
    parser = argparse.ArgumentParser(description="Seed demo users, posts, comments, bookmarks, and reports.")
    parser.add_argument("--posts", type=int, default=DEFAULT_POST_COUNT, help="Number of posts to create. Default: 200.")
    parser.add_argument("--dry-run", action="store_true", help="Show planned changes without writing to the database.")
    parser.add_argument("--reset-seeded", action="store_true", help="Delete seeded records before creating new ones.")
    return parser.parse_args()


def build_distribution(total_posts):
    if total_posts == DEFAULT_POST_COUNT:
        return POST_DISTRIBUTION.copy()

    base_total = sum(POST_DISTRIBUTION.values())
    distribution = {}
    assigned = 0
    categories = list(POST_DISTRIBUTION)
    for category in categories:
        count = max(1, round(total_posts * POST_DISTRIBUTION[category] / base_total))
        distribution[category] = count
        assigned += count

    while assigned != total_posts:
        category = categories[assigned % len(categories)]
        if assigned > total_posts and distribution[category] > 1:
            distribution[category] -= 1
            assigned -= 1
        elif assigned < total_posts:
            distribution[category] += 1
            assigned += 1
        else:
            break
    return distribution


def build_posts(total_posts):
    distribution = build_distribution(total_posts)
    posts = []
    for category, count in distribution.items():
        if category == "Announcements":
            for index in range(count):
                title, body, is_pinned, is_locked = ANNOUNCEMENTS[index % len(ANNOUNCEMENTS)]
                cycle = index // len(ANNOUNCEMENTS) + 1
                suffix = f" update {cycle}" if cycle > 1 else ""
                posts.append({
                    "title": f"{title}{suffix}",
                    "body": body,
                    "category": category,
                    "is_pinned": is_pinned,
                    "is_locked": is_locked,
                })
            continue

        topics = TOPICS[category]
        for index in range(count):
            title, body = topics[index % len(topics)]
            cycle = index // len(topics) + 1
            context = TITLE_CONTEXTS[(cycle - 1) % len(TITLE_CONTEXTS)]
            posts.append({
                "title": f"{title} {context}",
                "body": body,
                "category": category,
                "is_pinned": False,
                "is_locked": False,
            })
    return posts


def reset_seeded_records(dry_run):
    seeded_users = db_session.query(User).filter(
        or_(
            User.email.like(f"%@{SEED_EMAIL_DOMAIN}"),
            User.email.like(f"%@{OLD_SEED_EMAIL_DOMAIN}"),
            User.username.in_(LEGACY_SEEDED_USERNAMES),
        )
    ).all()
    seeded_user_ids = [user.id for user in seeded_users]
    generated_titles = {post["title"] for post in build_posts(DEFAULT_POST_COUNT)}
    seeded_posts = db_session.query(Post).filter(
        or_(
            Post.title.like(f"{OLD_SEED_TITLE_PREFIX}%"),
            Post.title.in_(generated_titles),
            Post.title.in_(LEGACY_SEEDED_POST_TITLES),
        )
    ).all()
    seeded_post_ids = [post.id for post in seeded_posts]

    seeded_comments = db_session.query(Comment).filter(
        or_(
            Comment.user_id.in_(seeded_user_ids) if seeded_user_ids else False,
            Comment.post_id.in_(seeded_post_ids) if seeded_post_ids else False,
        )
    ).all()
    seeded_comment_ids = [comment.id for comment in seeded_comments]

    reports_query = db_session.query(Report)
    seeded_reports = reports_query.filter(
        or_(
            Report.reporter_user_id.in_(seeded_user_ids) if seeded_user_ids else False,
            Report.post_id.in_(seeded_post_ids) if seeded_post_ids else False,
            Report.comment_id.in_(seeded_comment_ids) if seeded_comment_ids else False,
        )
    ).all()

    bookmarks_query = db_session.query(Bookmark)
    seeded_bookmarks = bookmarks_query.filter(
        or_(
            Bookmark.user_id.in_(seeded_user_ids) if seeded_user_ids else False,
            Bookmark.post_id.in_(seeded_post_ids) if seeded_post_ids else False,
        )
    ).all()

    print("Reset seeded records:")
    print(f"  bookmarks: {len(seeded_bookmarks)}")
    print(f"  reports:   {len(seeded_reports)}")
    print(f"  comments:  {len(seeded_comments)}")
    print(f"  posts:     {len(seeded_posts)}")
    print(f"  users:     {len(seeded_users)}")

    if dry_run:
        return

    for record in seeded_bookmarks + seeded_reports + seeded_comments + seeded_posts + seeded_users:
        db_session.delete(record)
    db_session.commit()


def create_users(dry_run):
    users = []
    created = 0
    skipped = 0
    password_hash = generate_password_hash(DEFAULT_PASSWORD, method="scrypt")

    for username, email, role, verified in SEEDED_USERS:
        existing = db_session.query(User).filter(
            or_(User.username == username, User.email == email)
        ).first()
        if existing:
            users.append(existing)
            skipped += 1
            continue

        created += 1
        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            role=role,
            account_active=True,
            email_verified=verified,
        )
        users.append(user)
        if not dry_run:
            db_session.add(user)

    if not dry_run:
        db_session.flush()
    print(f"Users: {created} created, {skipped} skipped")
    return users


def create_posts(posts_data, users, dry_run):
    verified_users = [user for user in users if user.email_verified]
    admin_users = [user for user in verified_users if user.role == "admin"]
    posts = []
    created = 0
    skipped = 0
    now = dt.datetime.now(dt.UTC)

    for index, post_data in enumerate(posts_data):
        existing = db_session.query(Post).filter_by(title=post_data["title"]).first()
        if existing:
            posts.append(existing)
            skipped += 1
            continue

        author_pool = admin_users if post_data["category"] == "Announcements" else verified_users
        post = Post(
            title=post_data["title"],
            category=post_data["category"],
            body=post_data["body"],
            user_id=random.choice(author_pool).id,
            is_pinned=post_data["is_pinned"],
            is_locked=post_data["is_locked"],
            created_at=random_past_datetime(now, index),
        )
        posts.append(post)
        created += 1
        if not dry_run:
            db_session.add(post)

    if not dry_run:
        db_session.flush()
    print(f"Posts: {created} created, {skipped} skipped")
    return posts


def random_past_datetime(now, index):
    # Spread demo posts across roughly three months with varied clock times.
    days_back = random.randint(0, 89)
    hour = random.randint(7, 23)
    minute = random.choice((0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55))
    second = random.randint(0, 59)
    timestamp = now - dt.timedelta(days=days_back)
    timestamp = timestamp.replace(hour=hour, minute=minute, second=second, microsecond=0)
    return timestamp - dt.timedelta(minutes=index % 17)


def create_comments(posts, users, dry_run):
    comment_authors = [user for user in users if user.email_verified and user.role != "admin"]
    created = 0

    for post in posts:
        if post.is_locked or db_session.query(Comment).filter_by(post_id=post.id).first():
            continue
        for offset in range(random.randint(2, 6)):
            comment = Comment(
                post_id=post.id,
                user_id=random.choice(comment_authors).id,
                body=random.choice(COMMENT_BODIES),
                created_at=post.created_at + dt.timedelta(minutes=15 * (offset + 1)),
            )
            created += 1
            if not dry_run:
                db_session.add(comment)

    if not dry_run:
        db_session.flush()
    print(f"Comments: {created} created")


def create_bookmarks(posts, users, dry_run):
    bookmark_users = [user for user in users if user.email_verified and user.role != "admin"]
    bookmarkable_posts = [post for post in posts if not post.is_deleted]
    created = 0

    for user in bookmark_users:
        for post in random.sample(bookmarkable_posts, k=min(8, len(bookmarkable_posts))):
            exists = db_session.query(Bookmark).filter_by(user_id=user.id, post_id=post.id).first()
            if exists:
                continue
            created += 1
            if not dry_run:
                db_session.add(Bookmark(user_id=user.id, post_id=post.id))

    if not dry_run:
        db_session.flush()
    print(f"Bookmarks: {created} created")


def create_reports(posts, users, dry_run):
    reporters = [user for user in users if user.email_verified and user.role != "admin"]
    reportable_posts = [post for post in posts if post.category != "Announcements"]
    created = 0
    statuses = ["open", "open", "open", "resolved", "resolved", "dismissed"]

    for post in random.sample(reportable_posts, k=min(15, len(reportable_posts))):
        exists = db_session.query(Report).filter_by(post_id=post.id).first()
        if exists:
            continue
        status = random.choice(statuses)
        report = Report(
            reporter_user_id=random.choice(reporters).id,
            post_id=post.id,
            reason=random.choice(REPORT_REASONS),
            details="Seeded moderation example for admin dashboard testing.",
            status=status,
            resolution_notes="Reviewed during seed data setup." if status != "open" else None,
            resolved_at=dt.datetime.now(dt.UTC) if status != "open" else None,
        )
        created += 1
        if not dry_run:
            db_session.add(report)

    if not dry_run:
        db_session.flush()
    print(f"Reports: {created} created")


def main():
    args = parse_args()
    random.seed(SEED)

    app = create_app()
    with app.app_context():
        Base.metadata.create_all(bind=app.db_engine)
        posts_data = build_posts(args.posts)

        print("===================================================")
        print("SEED DATA PLAN")
        print("===================================================")
        print(f"Dry run: {args.dry_run}")
        print(f"Reset seeded records first: {args.reset_seeded}")
        print(f"Users planned: {len(SEEDED_USERS)}")
        print(f"Posts planned: {len(posts_data)}")
        for category, count in build_distribution(args.posts).items():
            print(f"  {category}: {count}")

        if args.reset_seeded:
            reset_seeded_records(args.dry_run)

        users = create_users(args.dry_run)
        posts = create_posts(posts_data, users, args.dry_run)
        create_comments(posts, users, args.dry_run)
        create_bookmarks(posts, users, args.dry_run)
        create_reports(posts, users, args.dry_run)

        if args.dry_run:
            db_session.rollback()
            print("Dry run complete. No database changes were written.")
            return

        db_session.commit()

        print("===================================================")
        print("SEEDING COMPLETED SUCCESSFULLY")
        print("===================================================")
        print("Default password for all seeded users:")
        print(DEFAULT_PASSWORD)


if __name__ == "__main__":
    main()
