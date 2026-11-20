
import os
import io
import re
import sqlite3
import secrets
import zipfile

from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, send_file, session, flash, jsonify
)

from werkzeug.security import (
    generate_password_hash, check_password_hash
)

from PIL import Image
import fitz


app = Flask(__name__)

# Set a stable SECRET_KEY in Render environment variables.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

DB = os.environ.get("DATABASE_PATH", "rakshit.db")


TOOLS = [
    ("PDF Merge", "pdf-merge", "Combine multiple PDF files."),
    ("Split PDF", "pdf-split", "Split a PDF into individual pages."),
    ("Compress PDF", "pdf-compress", "Reduce PDF file size."),
    ("PDF to JPG", "pdf-to-jpg", "Convert PDF pages into images."),
    ("JPG to PDF", "jpg-to-pdf", "Convert images into a PDF."),
    ("Rotate PDF", "pdf-rotate", "Rotate PDF pages."),
    ("Protect PDF", "pdf-protect", "Add a password to your PDF."),
    ("Watermark PDF", "pdf-watermark", "Add a text watermark to your PDF."),
    ("Image Converter", "image-converter", "Convert images to PNG, JPG or WEBP."),
    ("Image Compress", "image-compress", "Compress JPG, PNG or WEBP images."),
    ("Background Remover", "background-remover", "Requires an AI background-removal engine."),
    ("Watermark Remover", "watermark-remover", "For images you own or are authorized to edit."),
    ("AI Image Creator", "image-creator", "Requires an image-generation service."),
    ("PDF to Word", "pdf-to-word", "Advanced conversion service required."),
    ("PDF to Excel", "pdf-to-excel", "Advanced conversion service required."),
    ("PDF to PowerPoint", "pdf-to-powerpoint", "Advanced conversion service required."),
    ("Word to PDF", "word-to-pdf", "LibreOffice service required."),
    ("PowerPoint to PDF", "powerpoint-to-pdf", "LibreOffice service required."),
    ("Excel to PDF", "excel-to-pdf", "LibreOffice service required."),
    ("Edit PDF", "edit-pdf", "PDF editing service required."),
    ("Sign PDF", "sign-pdf", "Signature editor required."),
    ("Unlock PDF", "unlock-pdf", "Requires the PDF password."),
    ("Organize PDF", "organize-pdf", "PDF page organizer required."),
    ("PDF to PDF/A", "pdf-to-pdfa", "PDF/A conversion engine required."),
    ("Repair PDF", "repair-pdf", "Advanced PDF repair required."),
    ("Page Numbers", "page-numbers", "Page numbering engine required."),
    ("OCR PDF", "ocr-pdf", "OCR engine required."),
    ("Compare PDF", "compare-pdf", "PDF comparison engine required."),
    ("Redact PDF", "redact-pdf", "Permanent redaction engine required."),
    ("Crop PDF", "crop-pdf", "PDF cropping engine required."),
    ("PDF Forms", "pdf-forms", "PDF form editor required."),
    ("HTML to PDF", "html-to-pdf", "HTML rendering engine required."),
    ("AI Summarizer", "ai-summarizer", "AI service required."),
    ("Translate PDF", "translate-pdf", "Translation service required."),
    ("PDF to Markdown", "pdf-to-markdown", "Extract PDF text as Markdown.")
]


# ---------------- DATABASE ----------------

def db():
    con = sqlite3.connect(DB)
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


init_db()


# ---------------- HELPERS ----------------

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to view your profile.")
            return redirect(url_for("login"))
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


# ---------------- COMMON PAGE DATA ----------------

@app.context_processor
def common():
    return {
        "current_user": session.get("email"),
        "tools": TOOLS
    }


# ---------------- MAIN PAGES ----------------

@app.route("/")
def home():
    return render_template("home.html", tools=TOOLS)


@app.route("/tools/<slug>")
def tool_page(slug):
    tool = next((t for t in TOOLS if t[1] == slug), None)

    if not tool:
        return "Tool not found", 404

    return render_template("tool.html", tool=tool)


@app.route("/settings")
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

                    session.clear()
                    session["user_id"] = cur.lastrowid
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
            session["user_id"] = user["id"]
            session["email"] = user["email"]

            return redirect(url_for("home"))

        flash("Email or password is incorrect.")

    return render_template("auth.html", mode="Sign in")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


# ---------------- CONVERSION ENGINE ----------------

@app.route("/convert/<slug>", methods=["POST"])
def convert(slug):

    allowed_slugs = {tool[1] for tool in TOOLS}

    if slug not in allowed_slugs:
        return jsonify(error="Unknown tool."), 404

    try:

        # PDF MERGE: accepts multiple files.
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

            return output_file(
                result, "merged.pdf", "application/pdf"
            )


        # COMPARE PDF is not yet implemented.
        if slug == "compare-pdf":
            return jsonify(
                error="PDF comparison engine is not configured yet."
            ), 501


        # Other tools require one uploaded file.
        uploaded = request.files.get("file")

        if not uploaded or not uploaded.filename:
            return jsonify(error="Choose a file first."), 400

        data = uploaded.read()

        if not data:
            return jsonify(error="The uploaded file is empty."), 400


        # PDF SPLIT: creates a ZIP containing individual pages.
        if slug == "pdf-split":

            doc = get_pdf(data)
            memory = io.BytesIO()

            with zipfile.ZipFile(
                memory, "w", zipfile.ZIP_DEFLATED
            ) as archive:

                for index in range(len(doc)):

                    page_doc = fitz.open()
                    page_doc.insert_pdf(doc, from_page=index, to_page=index)

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


        # PDF COMPRESS
        if slug == "pdf-compress":

            doc = get_pdf(data)

            result = doc.tobytes(
                garbage=4,
                deflate=True,
                clean=True
            )

            doc.close()

            return output_file(
                result, "compressed.pdf", "application/pdf"
            )


        # PDF ROTATE
        if slug == "pdf-rotate":

            doc = get_pdf(data)

            angle = int(request.form.get("angle", "90"))

            if angle not in (90, 180, 270):
                doc.close()
                return jsonify(error="Choose 90, 180 or 270 degrees."), 400

            for page in doc:
                page.set_rotation((page.rotation + angle) % 360)

            result = doc.tobytes()
            doc.close()

            return output_file(
                result, "rotated.pdf", "application/pdf"
            )


        # PDF PROTECT
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


        # PDF WATERMARK
        if slug == "pdf-watermark":

            text = request.form.get(
                "watermark_text",
                "Rakshit File Converter"
            ).strip()

            if not text or len(text) > 100:
                return jsonify(
                    error="Enter watermark text up to 100 characters."
                ), 400

            doc = get_pdf(data)

            for page in doc:
                rect = page.rect

                page.insert_text(
                    fitz.Point(rect.width * 0.20, rect.height * 0.50),
                    text,
                    fontsize=24,
                    color=(0.65, 0.65, 0.65),
                    overlay=True
                )

            result = doc.tobytes()
            doc.close()

            return output_file(
                result, "watermarked.pdf", "application/pdf"
            )


        # PDF TO JPG: converts the first page.
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


        # PDF TO MARKDOWN
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


        # JPG TO PDF
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


        # IMAGE CONVERTER AND COMPRESSOR
        if slug in ("image-converter", "image-compress"):

            image = safe_image(data)

            fmt = request.form.get("format", "WEBP").upper()

            if fmt not in ("PNG", "JPEG", "WEBP"):
                return jsonify(error="Choose PNG, JPEG or WEBP."), 400

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
                extension = "png"
                mimetype = "image/png"

            elif fmt == "JPEG":
                image.save(
                    buffer,
                    format="JPEG",
                    quality=80,
                    optimize=True
                )
                extension = "jpg"
                mimetype = "image/jpeg"

            else:
                image.save(
                    buffer,
                    format="WEBP",
                    quality=80,
                    method=4
                )
                extension = "webp"
                mimetype = "image/webp"

            buffer.seek(0)

            return send_file(
                buffer,
                as_attachment=True,
                download_name=f"converted.{extension}",
                mimetype=mimetype
            )


        # Other tools are not yet configured.
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


# ---------------- PWA ----------------

@app.route("/manifest.webmanifest")
def manifest():
    return app.send_static_file("manifest.webmanifest")


@app.route("/service-worker.js")
def sw():
    return app.send_static_file("service-worker.js")


# ---------------- HEALTH CHECK ----------------

@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
