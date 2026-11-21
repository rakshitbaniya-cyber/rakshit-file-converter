
import os
import io
import re
import sqlite3
import json
import urllib.request
import secrets
import zipfile
import uuid

from datetime import timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    send_file, session, flash, jsonify, send_from_directory,
    Response
)

from werkzeug.security import (
    generate_password_hash, check_password_hash
)
from werkzeug.utils import secure_filename

from PIL import Image
import fitz


# ---------------- APP CONFIGURATION ----------------

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "true").lower() == "true"
)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DB = os.environ.get(
    "DATABASE_PATH",
    os.path.join(BASE_DIR, "instance", "toolify.db")
)

UPLOAD_FOLDER = os.environ.get(
    "UPLOAD_FOLDER",
    os.path.join(BASE_DIR, "instance", "uploads")
)

os.makedirs(os.path.dirname(DB), exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------- TOOLS ----------------

TOOLS = [
    ("PDF Merge", "pdf-merge", "Combine multiple PDF files."),
    ("Split PDF", "pdf-split", "Split a PDF into individual pages."),
    ("Compress PDF", "pdf-compress", "Reduce PDF file size."),
    ("PDF to JPG", "pdf-to-jpg", "Convert PDF pages into images."),
    ("JPG to PDF", "jpg-to-pdf", "Convert images into a PDF."),
    ("Rotate PDF", "pdf-rotate", "Rotate PDF pages."),
    ("Protect PDF", "pdf-protect", "Add a password to your PDF."),
    ("Watermark PDF", "pdf-watermark", "Add text to your PDF pages."),
    ("Image Converter", "image-converter", "Convert images to PNG, JPG or WEBP."),
    ("Image Compress", "image-compress", "Reduce image file size."),
    ("Background Remover", "background-remover", "Remove an image background and choose a new color."),
    ("Watermark Remover", "watermark-remover", "For images you own or are authorized to edit."),
    ("AI Image Creator", "image-creator", "Create images from text descriptions."),
    ("PDF to Word", "pdf-to-word", "Convert PDF documents to Word."),
    ("PDF to Excel", "pdf-to-excel", "Extract PDF tables to Excel."),
    ("PDF to PowerPoint", "pdf-to-powerpoint", "Convert PDF pages to PowerPoint."),
    ("Word to PDF", "word-to-pdf", "Convert Word documents to PDF."),
    ("PowerPoint to PDF", "powerpoint-to-pdf", "Convert presentations to PDF."),
    ("Excel to PDF", "excel-to-pdf", "Convert spreadsheets to PDF."),
    ("Edit PDF", "edit-pdf", "Edit PDF documents."),
    ("Sign PDF", "sign-pdf", "Add a signature to a PDF."),
    ("Unlock PDF", "unlock-pdf", "Open a PDF using its existing password."),
    ("Organize PDF", "organize-pdf", "Rearrange PDF pages."),
    ("PDF to PDF/A", "pdf-to-pdfa", "Convert documents to PDF/A."),
    ("Repair PDF", "repair-pdf", "Try to repair a damaged PDF."),
    ("Page Numbers", "page-numbers", "Add page numbers to a PDF."),
    ("OCR PDF", "ocr-pdf", "Extract text from scanned PDFs."),
    ("Compare PDF", "compare-pdf", "Compare two PDF documents."),
    ("Redact PDF", "redact-pdf", "Permanently remove sensitive PDF content."),
    ("Crop PDF", "crop-pdf", "Crop PDF pages."),
    ("PDF Forms", "pdf-forms", "Work with PDF forms."),
    ("HTML to PDF", "html-to-pdf", "Convert HTML documents to PDF."),
    ("AI Summarizer", "ai-summarizer", "Summarize documents using AI."),
    ("Translate PDF", "translate-pdf", "Translate PDF document text."),
    ("PDF to Markdown", "pdf-to-markdown", "Extract PDF text as Markdown.")
]


# ---------------- DATABASE ----------------

def db():
    con = sqlite3.connect(DB, timeout=20)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Add profile columns to existing databases safely.
        existing = {
            row["name"]
            for row in con.execute("PRAGMA table_info(users)").fetchall()
        }
        migrations = {
            "profile_photo": "ALTER TABLE users ADD COLUMN profile_photo TEXT",
            "avatar": "ALTER TABLE users ADD COLUMN avatar TEXT",
            "caption": "ALTER TABLE users ADD COLUMN caption TEXT",
            "role": "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'",
            "premium_plan": "ALTER TABLE users ADD COLUMN premium_plan TEXT DEFAULT 'free'",
            "premium_expiry": "ALTER TABLE users ADD COLUMN premium_expiry TIMESTAMP"
        }
        for column, sql in migrations.items():
            if column not in existing:
                con.execute(sql)

        # Activate the configured Toolify admin
        admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()

        if admin_email:
            con.execute(
                "UPDATE users SET role = 'admin' WHERE email = ?",
                (admin_email,)
            )
        # Create feedback table.
        con.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                rating INTEGER NOT NULL,
                comment TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        # Add approval status safely.
        existing_feedback_columns = {
            row["name"]
            for row in con.execute("PRAGMA table_info(feedback)").fetchall()
        }

        if "status" not in existing_feedback_columns:
            con.execute("""
                ALTER TABLE feedback
                ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'
            """)
init_db()

# ---------------- GOOGLE SHEETS SYNC ----------------

def sync_to_google_sheet(sheet_name, values):
    webhook_url = os.environ.get("TOOLIFY_SHEETS_WEBHOOK_URL")
    sync_secret = os.environ.get("TOOLIFY_SYNC_SECRET")

    if not webhook_url or not sync_secret:
        app.logger.warning("Google Sheets sync is not configured.")
        return False

    payload = {
        "secret": sync_secret,
        "sheet": sheet_name,
        "values": values
    }

    try:
        data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=15) as response:
            result = json.loads(response.read().decode("utf-8"))

        if result.get("success") is True:
            return True

        app.logger.error("Google Sheets rejected a sync request.")
        return False

    except Exception:
        app.logger.exception("Google Sheets sync failed.")
        return False

# ---------------- HELPERS ----------------

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in first.")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped
def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        user = current_user_record()
        admin_email = os.environ.get(
            "ADMIN_EMAIL", ""
        ).strip().lower()

        if not user or not admin_email:
            return "Access denied.", 403

        if user["email"].strip().lower() != admin_email:
            return "Access denied.", 403

        return fn(*args, **kwargs)

    return wrapped
def get_pdf(data):
    doc = fitz.open(stream=data, filetype="pdf")

    if doc.is_encrypted:
        doc.close()
        raise ValueError("This PDF is password protected.")

    if len(doc) == 0:
        doc.close()
        raise ValueError("This PDF has no pages.")

    return doc


def output_file(data, filename, mimetype):
    buf = io.BytesIO(data)
    buf.seek(0)

    return send_file(
        buf,
        as_attachment=True,
        download_name=filename,
        mimetype=mimetype
    )


def safe_image(data):
    image = Image.open(io.BytesIO(data))
    image.load()

    if image.width * image.height > 40000000:
        raise ValueError("Image dimensions are too large.")

    return image


def current_user_record():
    user_id = session.get("user_id")

    if not user_id:
        return None

    with db() as con:
        return con.execute(
            "SELECT * FROM users WHERE id=?",
            (user_id,)
        ).fetchone()


# ---------------- COMMON TEMPLATE DATA ----------------

@app.context_processor
def common():
    return {
        "current_user": session.get("email"),
        "tools": TOOLS,
        "site_name": "Toolify",
        "site_description": (
            "Toolify offers easy online PDF tools, image tools, "
            "file conversion and creative tools."
        )
    }


# ---------------- HOME AND TOOL PAGES ----------------


@app.route("/")
def home():
    with db() as con:
        approved_feedback = con.execute("""
            SELECT feedback.rating, feedback.comment,
                   feedback.created_at, users.email
            FROM feedback
            LEFT JOIN users ON feedback.user_id = users.id
            WHERE feedback.status = 'approved'
            ORDER BY feedback.created_at DESC
        """).fetchall()

    return render_template(
        "home.html",
        tools=TOOLS,
        approved_feedback=approved_feedback
    )



@app.route("/tools/<slug>")
def tool_page(slug):
    tool = next((t for t in TOOLS if t[1] == slug), None)

    if not tool:
        return "Tool not found", 404

    return render_template("tool.html", tool=tool)


@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

# ---------------- REGISTRATION ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or len(password) < 10:
            flash("Enter a valid email and password of at least 10 characters.")
        else:
            try:
                with db() as con:
                    cur = con.execute(
                        "INSERT INTO users(email,password_hash) VALUES(?,?)",
                        (email, generate_password_hash(password))
                    )
                    user_id = cur.lastrowid

                sync_to_google_sheet(
                    "Registration Details",
                    [
                        str(user_id),
                        email,
                        "",
                        "",
                        "user",
                        "Active",
                        "",
                        "Website Registration"
                    ]
                )

                session.clear()
                session.permanent = True
                session["user_id"] = user_id
                session["email"] = email

                return redirect(url_for("home"))

            except sqlite3.IntegrityError:
                flash("This email is already registered.")

    return render_template("auth.html", mode="Register")

# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with db() as con:
            user = con.execute(
                "SELECT * FROM users WHERE email=?",
                (email,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["email"] = user["email"]

            return redirect(url_for("home"))

        flash("Email or password is incorrect.")

    return render_template("auth.html", mode="Sign in")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------------- PROFILE ----------------

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user_record()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        caption = request.form.get("caption", "").strip()
        avatar = request.form.get("avatar", "").strip()

        allowed_avatars = [
            "😀", "😎", "🤖", "🦊", "🐼", "🐯", "🚀", "🎨"
        ]

        if len(caption) > 160:
            flash("Caption must be 160 characters or less.")
            return redirect(url_for("profile"))

        if avatar and avatar not in allowed_avatars:
            flash("Please choose a valid avatar.")
            return redirect(url_for("profile"))

        photo = request.files.get("profile_photo")
        photo_name = user["profile_photo"]

        if photo and photo.filename:
            try:
                photo_data = photo.read()
                image = safe_image(photo_data)

                if image.width > 3000 or image.height > 3000:
                    flash("Profile photo dimensions are too large.")
                    return redirect(url_for("profile"))

                extension = "png"
                photo_name = secrets.token_hex(16) + "." + extension

                image = image.convert("RGB")
                image.save(
                    os.path.join(UPLOAD_FOLDER, photo_name),
                    format="PNG"
                )

            except Exception:
                flash("Please upload a valid image.")
                return redirect(url_for("profile"))

        remove_photo = request.form.get("remove_photo") == "yes"

        if remove_photo and user["profile_photo"]:
            old_path = os.path.join(UPLOAD_FOLDER, user["profile_photo"])
            if os.path.isfile(old_path):
                os.remove(old_path)
            photo_name = None

        with db() as con:
            con.execute("""
                UPDATE users
                SET caption=?, avatar=?, profile_photo=?
                WHERE id=?
            """, (caption or None, avatar or None, photo_name, user["id"]))

        flash("Profile updated successfully.")
        return redirect(url_for("profile"))

    return render_template("profile.html", profile=user)


@app.route("/uploads/<filename>")
@login_required
def uploaded_profile_photo(filename):
    safe_name = os.path.basename(filename)

    with db() as con:
        allowed = con.execute(
            "SELECT id FROM users WHERE id=? AND profile_photo=?",
            (session["user_id"], safe_name)
        ).fetchone()

    if not allowed:
        return "Not found", 404

    return send_from_directory(UPLOAD_FOLDER, safe_name)


# ---------------- FEEDBACK ----------------
@app.route("/feedback", methods=["POST"])
def submit_feedback():
    rating_value = request.form.get("rating", "").strip()
    comment = request.form.get("comment", "").strip()

    try:
        rating = int(rating_value)
    except (ValueError, TypeError):
        return jsonify(error="Please select a rating."), 400

    if rating < 1 or rating > 5:
        return jsonify(error="Rating must be between 1 and 5."), 400

    if len(comment) > 2000:
        return jsonify(error="Comment must be 2000 characters or less."), 400

    user_id = session.get("user_id")
with db() as con:
    cur = con.execute("""
        INSERT INTO feedback(user_id, rating, comment, status)
        VALUES(?, ?, ?, 'pending')
    """, (user_id, rating, comment or None))

    feedback_id = cur.lastrowid

    user = con.execute(
        "SELECT email FROM users WHERE id = ?",
        (user_id,)
    ).fetchone() if user_id else None

    sync_to_google_sheet(
        "Feedback Details",
        [
            str(feedback_id),
            str(user_id or ""),
            user["email"] if user else "Guest",
            str(rating),
            comment or "",
            "",
            "Pending",
            ""
        ]
    )
    return jsonify(
        success=True,
        message="Thank you! Your feedback has been submitted and is awaiting admin approval."
    )
@app.route("/admin/feedback")
@login_required
@admin_required
def admin_feedback():
    with db() as con:
        feedback_rows = con.execute("""
            SELECT feedback.id, feedback.rating, feedback.comment,
                   feedback.created_at, feedback.status, users.email
            FROM feedback
            LEFT JOIN users ON feedback.user_id = users.id
            ORDER BY feedback.created_at DESC
        """).fetchall()

    return render_template(
        "admin_feedback.html",
        feedback=feedback_rows
    )

# Approve feedback
@app.route("/admin/feedback/<int:feedback_id>/approve", methods=["POST"])
@login_required
@admin_required
def approve_feedback(feedback_id):
    with db() as con:
        con.execute(
            "UPDATE feedback SET status = 'approved' WHERE id = ?",
            (feedback_id,)
        )

    flash("Feedback approved successfully.", "success")
    return redirect(url_for("admin_feedback"))


# Reject feedback
@app.route("/admin/feedback/<int:feedback_id>/reject", methods=["POST"])
@login_required
@admin_required
def reject_feedback(feedback_id):
    with db() as con:
        con.execute(
            "UPDATE feedback SET status = 'rejected' WHERE id = ?",
            (feedback_id,)
        )

    flash("Feedback rejected successfully.", "success")
    return redirect(url_for("admin_feedback"))
  
@app.route("/admin/feedback/export")
@login_required
@admin_required
def export_feedback():
    try:
        from openpyxl import Workbook
    except ImportError:
        return "Excel export package is missing.", 500

    with db() as con:
        rows = con.execute("""
            SELECT feedback.id, users.email, feedback.rating,
                   feedback.comment, feedback.created_at
            FROM feedback
            LEFT JOIN users ON feedback.user_id = users.id
            ORDER BY feedback.created_at DESC
        """).fetchall()

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Toolify Feedback"

    sheet.append([
        "Feedback ID", "User Email", "Rating",
        "Comment", "Date"
    ])

    for row in rows:
        sheet.append([
            row["id"],
            row["email"] or "Guest",
            row["rating"],
            row["comment"] or "",
            str(row["created_at"])
        ])

    for column in sheet.columns:
        max_length = max(
            len(str(cell.value or ""))
            for cell in column
        )
        sheet.column_dimensions[column[0].column_letter].width = min(
            max_length + 3, 45
        )

    buffer = io.BytesIO()
    workbook.save(buffer)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="toolify-feedback.xlsx",
        mimetype=(
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        )
    )


# ---------------- BACKGROUND REMOVER ----------------

@app.route("/background-remove", methods=["POST"])
def background_remove():
    uploaded = request.files.get("image")

    if not uploaded or not uploaded.filename:
        return jsonify(error="Please select an image."), 400

    try:
        data = uploaded.read()
        safe_image(data)

        try:
            from rembg import remove
        except ImportError:
            return jsonify(
                error="Background removal engine is not installed yet."
            ), 501

        result = remove(data)

        output = io.BytesIO(result)
        output.seek(0)

        return send_file(
            output,
            as_attachment=False,
            download_name="background-removed.png",
            mimetype="image/png"
        )

    except Exception:
        app.logger.exception("Background removal failed")
        return jsonify(
            error="Could not remove the background. Please try another image."
        ), 400


# ---------------- AI IMAGE CREATOR ----------------

@app.route("/generate-image", methods=["POST"])
@login_required
def generate_image():
    prompt = request.form.get("prompt", "").strip()

    if not prompt:
        return jsonify(error="Please describe the image you want."), 400

    if len(prompt) > 1000:
        return jsonify(error="Image description is too long."), 400

    return jsonify(
        error="Image generation service has not been connected yet."
    ), 501


# ---------------- CONVERSION ENGINE ----------------

@app.route("/convert/<slug>", methods=["POST"])
def convert(slug):
    allowed_slugs = {tool[1] for tool in TOOLS}

    if slug not in allowed_slugs:
        return jsonify(error="Unknown tool."), 404

    try:
        if slug == "pdf-merge":
            files = request.files.getlist("files")

            if len(files) < 2:
                return jsonify(error="Select at least two PDF files."), 400

            output = fitz.open()

            for item in files:
                if not item or not item.filename:
                    continue

                src = get_pdf(item.read())
                output.insert_pdf(src)
                src.close()

            if len(output) == 0:
                output.close()
                return jsonify(error="No valid PDF files selected."), 400

            result = output.tobytes(garbage=4, deflate=True)
            output.close()

            return output_file(result, "merged.pdf", "application/pdf")

        if slug == "compare-pdf":
            return jsonify(
                error="PDF comparison engine is not configured yet."
            ), 501

        uploaded = request.files.get("file")

        if not uploaded or not uploaded.filename:
            return jsonify(error="Choose a file first."), 400

        data = uploaded.read()

        if not data:
            return jsonify(error="The uploaded file is empty."), 400

        if slug == "pdf-split":
            doc = get_pdf(data)
            memory = io.BytesIO()

            with zipfile.ZipFile(
                memory, "w", zipfile.ZIP_DEFLATED
            ) as archive:
                for index in range(len(doc)):
                    page_doc = fitz.open()
                    page_doc.insert_pdf(
                        doc, from_page=index, to_page=index
                    )
                    archive.writestr(
                        f"page-{index + 1}.pdf",
                        page_doc.tobytes()
                    )
                    page_doc.close()

            doc.close()
            memory.seek(0)

            return send_file(
                memory,
                as_attachment=True,
                download_name="split-pages.zip",
                mimetype="application/zip"
            )

        if slug == "pdf-compress":
            doc = get_pdf(data)
            result = doc.tobytes(
                garbage=4, deflate=True, clean=True
            )
            doc.close()
            return output_file(
                result, "compressed.pdf", "application/pdf"
            )

        if slug == "pdf-rotate":
            doc = get_pdf(data)
            angle = int(request.form.get("angle", "90"))

            if angle not in (90, 180, 270):
                doc.close()
                return jsonify(
                    error="Choose 90, 180 or 270 degrees."
                ), 400

            for page in doc:
                page.set_rotation((page.rotation + angle) % 360)

            result = doc.tobytes()
            doc.close()
            return output_file(
                result, "rotated.pdf", "application/pdf"
            )

        if slug == "pdf-protect":
            password = request.form.get("pdf_password", "")

            if len(password) < 6:
                return jsonify(
                    error="Enter a PDF password of at least 6 characters."
                ), 400

            doc = get_pdf(data)
            result = doc.tobytes(
                encryption=fitz.PDF_ENCRYPT_AES_256,
                user_pw=password,
                owner_pw=secrets.token_urlsafe(24)
            )
            doc.close()
            return output_file(
                result, "protected.pdf", "application/pdf"
            )

        if slug == "pdf-watermark":
            watermark_text = request.form.get(
                "watermark_text", "Toolify"
            ).strip()

            if not watermark_text or len(watermark_text) > 100:
                return jsonify(
                    error="Enter watermark text up to 100 characters."
                ), 400

            doc = get_pdf(data)

            for page in doc:
                rect = page.rect
                page.insert_text(
                    fitz.Point(rect.width * 0.20, rect.height * 0.50),
                    watermark_text,
                    fontsize=24,
                    color=(0.65, 0.65, 0.65),
                    overlay=True
                )

            result = doc.tobytes()
            doc.close()
            return output_file(
                result, "watermarked.pdf", "application/pdf"
            )

        if slug == "pdf-to-jpg":
            doc = get_pdf(data)
            pix = doc[0].get_pixmap(
                matrix=fitz.Matrix(1.5, 1.5),
                alpha=False
            )
            result = pix.tobytes("jpeg")
            doc.close()
            return output_file(
                result, "page-1.jpg", "image/jpeg"
            )

        if slug == "pdf-to-markdown":
            doc = get_pdf(data)
            text_content = []

            for index, page in enumerate(doc):
                text_content.append(
                    f"# Page {index + 1}\n\n{page.get_text()}"
                )

            doc.close()
            result = "\n\n---\n\n".join(text_content).encode("utf-8")

            return output_file(
                result, "document.md", "text/markdown"
            )

        if slug == "jpg-to-pdf":
            image = safe_image(data).convert("RGB")
            buffer = io.BytesIO()
            image.save(buffer, format="PDF")
            buffer.seek(0)

            return send_file(
                buffer,
                as_attachment=True,
                download_name="image.pdf",
                mimetype="application/pdf"
            )

        if slug in ("image-converter", "image-compress"):
            image = safe_image(data)
            fmt = request.form.get("format", "WEBP").upper()

            if fmt not in ("PNG", "JPEG", "WEBP"):
                return jsonify(
                    error="Choose PNG, JPEG or WEBP."
                ), 400

            if fmt == "JPEG":
                if image.mode not in ("RGB", "L"):
                    image = image.convert("RGB")
            elif fmt == "PNG":
                if image.mode not in ("RGB", "RGBA", "L", "LA"):
                    image = image.convert("RGBA")
            else:
                if image.mode not in ("RGB", "RGBA"):
                    image = image.convert("RGBA")

            buffer = io.BytesIO()

            if fmt == "PNG":
                image.save(buffer, format="PNG", optimize=True)
                extension, mimetype = "png", "image/png"
            elif fmt == "JPEG":
                image.save(
                    buffer, format="JPEG",
                    quality=80, optimize=True
                )
                extension, mimetype = "jpg", "image/jpeg"
            else:
                image.save(
                    buffer, format="WEBP",
                    quality=80, method=4
                )
                extension, mimetype = "webp", "image/webp"

            buffer.seek(0)
            return send_file(
                buffer,
                as_attachment=True,
                download_name=f"converted.{extension}",
                mimetype=mimetype
            )

        return jsonify(
            error="This tool's processing engine is not available yet."
        ), 501

    except (ValueError, TypeError) as error:
        return jsonify(error=str(error)), 400

    except Exception:
        app.logger.exception("File conversion failed")
        return jsonify(
            error="Could not process this file. Check that the file is valid and try again."
        ), 400


# ---------------- SEO: SITEMAP AND ROBOTS ----------------

@app.route("/sitemap.xml")
def sitemap():
    pages = [
        url_for("home", _external=True),
        url_for("login", _external=True),
        url_for("register", _external=True)
    ]

    for tool in TOOLS:
        pages.append(
            url_for("tool_page", slug=tool[1], _external=True)
        )

    xml = ['<?xml version="1.0" encoding="UTF-8"?>']
    xml.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')

    for page in pages:
        xml.append("<url>")
        xml.append(f"<loc>{page}</loc>")
        xml.append("</url>")

    xml.append("</urlset>")

    return Response(
        "\n".join(xml),
        mimetype="application/xml"
    )


@app.route("/robots.txt")
def robots():
    content = (
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /admin/\n"
        "Disallow: /profile\n"
        "Disallow: /settings\n"
        f"Sitemap: {request.url_root.rstrip('/')}/sitemap.xml\n"
    )
    return Response(content, mimetype="text/plain")


# ---------------- PWA ----------------

@app.route("/manifest.webmanifest")
def manifest():
    return app.send_static_file("manifest.webmanifest")


@app.route("/service-worker.js")
def service_worker():
    return app.send_static_file("service-worker.js")


# ---------------- HEALTH CHECK ----------------

@app.route("/health")
def health():
    return {"status": "ok", "app": "Toolify"}


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
