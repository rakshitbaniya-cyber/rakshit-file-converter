import os, io, sqlite3, secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, send_file, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import fitz

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
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
    ("Background Remover", "background-remover", "Remove backgrounds from images (requires an optional AI service)."),
    ("Watermark Remover", "watermark-remover", "For images you own or are authorized to edit."),
    ("AI Image Creator", "image-creator", "Create images from a text prompt (requires an image-generation API)."),
    ("PDF to Word", "pdf-to-word", "Convert PDF text to DOCX (advanced conversion service required)."),
    ("PDF to Excel", "pdf-to-excel", "Extract PDF tables (advanced conversion service required)."),
    ("PDF to PowerPoint", "pdf-to-powerpoint", "Convert PDF pages to slides (advanced conversion service required)."),
    ("Word to PDF", "word-to-pdf", "Convert DOCX to PDF (LibreOffice service required)."),
    ("PowerPoint to PDF", "powerpoint-to-pdf", "Convert PPTX to PDF (LibreOffice service required)."),
    ("Excel to PDF", "excel-to-pdf", "Convert XLSX to PDF (LibreOffice service required)."),
    ("Edit PDF", "edit-pdf", "Edit PDF content."),
    ("Sign PDF", "sign-pdf", "Add a signature to a PDF."),
    ("Unlock PDF", "unlock-pdf", "Unlock a PDF when you know its password."),
    ("Organize PDF", "organize-pdf", "Reorder or remove PDF pages."),
    ("PDF to PDF/A", "pdf-to-pdfa", "Create archival PDF/A files."),
    ("Repair PDF", "repair-pdf", "Attempt to repair damaged PDFs."),
    ("Page Numbers", "page-numbers", "Add page numbers."),
    ("OCR PDF", "ocr-pdf", "Recognize text in scanned PDFs (OCR engine required)."),
    ("Compare PDF", "compare-pdf", "Compare two PDF documents."),
    ("Redact PDF", "redact-pdf", "Permanently redact sensitive information."),
    ("Crop PDF", "crop-pdf", "Crop PDF pages."),
    ("PDF Forms", "pdf-forms", "Fill supported PDF forms."),
    ("HTML to PDF", "html-to-pdf", "Convert HTML pages to PDF."),
    ("AI Summarizer", "ai-summarizer", "Summarize documents (AI service required)."),
    ("Translate PDF", "translate-pdf", "Translate PDF text (translation service required)."),
    ("PDF to Markdown", "pdf-to-markdown", "Extract PDF text as Markdown.")
]


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")


init_db()


def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not session.get("user_id"):
            flash("Please sign in to view your profile.")
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapped


@app.context_processor
def common():
    return {"current_user": session.get("email"), "tools": TOOLS}


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


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or len(password) < 10:
            flash("Enter a valid email and a password of at least 10 characters.")
        else:
            try:
                with db() as con:
                    cur = con.execute(
                        "INSERT INTO users(email,password_hash) VALUES(?,?)",
                        (email, generate_password_hash(password))
                    )
                    session["user_id"] = cur.lastrowid
                    session["email"] = email
                return redirect(url_for("home"))
            except sqlite3.IntegrityError:
                flash("This email is already registered.")
    return render_template("auth.html", mode="Register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        with db() as con:
            user = con.execute(
                "SELECT * FROM users WHERE email=?", (email,)
            ).fetchone()

        if user and check_password_hash(
            user["password_hash"], request.form.get("password", "")
        ):
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


@app.route("/convert/<slug>", methods=["POST"])
def convert(slug):
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(error="Choose a file first."), 400

    data = f.read()

    try:
        if slug == "pdf-merge":
            files = request.files.getlist("files")
            out = fitz.open()

            for item in files:
                if item and item.filename:
                    src = fitz.open(
                        stream=item.read(), filetype="pdf"
                    )
                    out.insert_pdf(src)
                    src.close()

            buf = io.BytesIO(out.tobytes())
            out.close()
            return send_file(
                buf,
                as_attachment=True,
                download_name="merged.pdf",
                mimetype="application/pdf"
            )

        if slug == "pdf-compress":
            doc = fitz.open(stream=data, filetype="pdf")
            buf = io.BytesIO(
                doc.tobytes(garbage=4, deflate=True, clean=True)
            )
            doc.close()
            return send_file(
                buf,
                as_attachment=True,
                download_name="compressed.pdf",
                mimetype="application/pdf"
            )

        if slug == "pdf-rotate":
            doc = fitz.open(stream=data, filetype="pdf")
            angle = int(request.form.get("angle", "90")) % 360

            for page in doc:
                page.set_rotation((page.rotation + angle) % 360)

            buf = io.BytesIO(doc.tobytes())
            doc.close()
            return send_file(
                buf,
                as_attachment=True,
                download_name="rotated.pdf",
                mimetype="application/pdf"
            )

        if slug == "pdf-protect":
            password = request.form.get("pdf_password", "")
            if len(password) < 6:
                return jsonify(
                    error="Use a password of at least 6 characters."
                ), 400

            doc = fitz.open(stream=data, filetype="pdf")
            protected = doc.tobytes(
                encryption=fitz.PDF_ENCRYPT_AES_256,
                user_pw=password,
                owner_pw=secrets.token_urlsafe(24)
            )
            doc.close()
            return send_file(
                io.BytesIO(protected),
                as_attachment=True,
                download_name="protected.pdf",
                mimetype="application/pdf"
            )

        if slug in ("image-converter", "image-compress"):
            im = Image.open(io.BytesIO(data))
            fmt = request.form.get("format", "WEBP").upper()

            if fmt not in ("PNG", "JPEG", "WEBP"):
                fmt = "WEBP"

            if fmt == "JPEG" and im.mode not in ("RGB", "L"):
                im = im.convert("RGB")

            buf = io.BytesIO()
            im.save(buf, format=fmt, quality=82, optimize=True)
            buf.seek(0)

            ext = "jpg" if fmt == "JPEG" else fmt.lower()
            return send_file(
                buf,
                as_attachment=True,
                download_name=f"converted.{ext}",
                mimetype=f"image/{ext}"
            )

        if slug == "jpg-to-pdf":
            im = Image.open(io.BytesIO(data)).convert("RGB")
            buf = io.BytesIO()
            im.save(buf, format="PDF")
            buf.seek(0)
            return send_file(
                buf,
                as_attachment=True,
                download_name="image.pdf",
                mimetype="application/pdf"
            )

        if slug == "pdf-to-jpg":
            doc = fitz.open(stream=data, filetype="pdf")
            if not doc:
                return jsonify(error="PDF is empty."), 400

            pix = doc[0].get_pixmap(
                matrix=fitz.Matrix(1.5, 1.5), alpha=False
            )
            buf = io.BytesIO(pix.tobytes("jpeg"))
            doc.close()
            return send_file(
                buf,
                as_attachment=True,
                download_name="page-1.jpg",
                mimetype="image/jpeg"
            )

        return jsonify(
            error="This tool page is ready, but its processing engine is not configured yet. See README for requirements."
        ), 501

    except Exception as e:
        return jsonify(error=f"Could not process this file: {str(e)}"), 400


@app.route("/manifest.webmanifest")
def manifest():
    return app.send_static_file("manifest.webmanifest")


@app.route("/service-worker.js")
def sw():
    return app.send_static_file("service-worker.js")


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
