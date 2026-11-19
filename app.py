
import os
import io
import re
import html
import secrets
import sqlite3
import smtplib
from email.message import EmailMessage
from datetime import timedelta
from pathlib import Path
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse
from xml.sax.saxutils import escape

import pymupdf
from PIL import Image
from flask import (
    Flask, request, session, redirect, url_for, send_file,
    abort, render_template_string, flash, make_response
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from openpyxl import Workbook
from waitress import serve

# ==================================================
# CONFIGURATION
# ==================================================

BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("DATA_DIR", str(BASE / "data")))
UPLOADS = DATA / "uploads"
OUTPUTS = DATA / "outputs"
DB = DATA / "rakshit.db"

for folder in (DATA, UPLOADS, OUTPUTS):
    folder.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)

SITE_NAME = "Rakshit File Converter"
SITE_URL = os.environ.get(
    "SITE_URL",
    "https://rakshit-file-converter-1.onrender.com"
).rstrip("/")

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "bmp"}
ALLOWED_PDF_EXTENSIONS = {"pdf"}


# ==================================================
# DATABASE
# ==================================================

def get_db():
    connection = sqlite3.connect(DB)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TEXT NOT NULL
            )
        """)

        columns = [
            row["name"] for row in db.execute("PRAGMA table_info(users)")
        ]

        if "status" not in columns:
            db.execute(
                "ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'"
            )

        db.execute("""
            CREATE TABLE IF NOT EXISTS activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS contact_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER DEFAULT 0
            )
        """)

        db.commit()


init_db()


# ==================================================
# GENERAL HELPERS
# ==================================================

def now_text():
    return datetime.now(timezone.utc).isoformat()


def log_activity(user_id, action):
    with get_db() as db:
        db.execute(
            "INSERT INTO activity (user_id, action, created_at) VALUES (?, ?, ?)",
            (user_id, action, now_text())
        )
        db.commit()


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    with get_db() as db:
        return db.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user = current_user()

        if not user:
            flash("Please login first.", "error")
            return redirect(url_for("login"))

        if user["status"] != "active":
            session.clear()
            flash("Your account is blocked.", "error")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user = current_user()

        if not user or user["role"] != "admin":
            abort(403)

        return function(*args, **kwargs)

    return wrapper


# ==================================================
# CSRF PROTECTION
# ==================================================

def csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)

    return session["_csrf_token"]


@app.context_processor
def inject_template_values():
    return {
        "csrf_token": csrf_token,
        "current_user": current_user(),
        "site_name": SITE_NAME
    }


@app.before_request
def protect_forms():
    if request.method == "POST":
        sent_token = request.form.get("csrf_token", "")
        saved_token = session.get("_csrf_token", "")

        if not sent_token or not saved_token:
            abort(400, "Invalid form token. Refresh and try again.")

        if not secrets.compare_digest(sent_token, saved_token):
            abort(400, "Invalid form token. Refresh and try again.")


# ==================================================
# PASSWORD RESET EMAIL
# ==================================================

def send_reset_email(email, token):
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    smtp_from = os.environ.get("SMTP_FROM", smtp_user or "")

    if not all([smtp_host, smtp_user, smtp_password, smtp_from]):
        return False

    reset_link = f"{SITE_URL}/reset-password/{token}"

    message = EmailMessage()
    message["Subject"] = "Rakshit File Converter - Password Reset"
    message["From"] = smtp_from
    message["To"] = email
    message.set_content(
        "You requested a password reset.\n\n"
        f"Open this link to reset your password:\n{reset_link}\n\n"
        "This link expires in 30 minutes. "
        "If you did not request this, ignore this email."
    )

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(message)
        return True
    except Exception:
        app.logger.exception("Password reset email could not be sent")
        return False
