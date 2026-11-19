
import os
import io
import re
import html
import secrets
import sqlite3
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

SITE_URL = os.environ.get("SITE_URL", "").strip().rstrip("/")
if SITE_URL:
    parsed = urlparse(SITE_URL)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("SITE_URL must be a valid https:// website URL")

app = Flask(__name__)
@app.route("/google2e95d266378fddc4.html")
def google_site_verification():
    return send_file(
        BASE / "google2e95d266378fddc4.html",
        mimetype="text/html"
    )
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "0") == "1"
)

# ==================================================
# DATABASE
# ==================================================

def connect_db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with connect_db() as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created TEXT NOT NULL
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS activity(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            filename TEXT,
            created TEXT
        )
        """)

    admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "")

    if admin_email and admin_password:
        if len(admin_password) < 12:
            raise ValueError("ADMIN_PASSWORD must be at least 12 characters")
        with connect_db() as con:
            existing = con.execute(
                "SELECT id FROM users WHERE email=?", (admin_email,)
            ).fetchone()
            if existing:
                con.execute(
                    "UPDATE users SET role='admin' WHERE email=?",
                    (admin_email,)
                )
            else:
                con.execute("""
                INSERT INTO users(name,email,password,role,created)
                VALUES(?,?,?,?,?)
                """, (
                    "Administrator", admin_email,
                    generate_password_hash(admin_password),
                    "admin", datetime.now(timezone.utc).isoformat()
                ))

init_db()

# ==================================================
# SECURITY / CSRF
# ==================================================

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]

app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def verify_csrf():
    if request.method == "POST":
        saved = session.get("csrf", "")
        sent = request.form.get("csrf", "")
        if not saved or not sent or not secrets.compare_digest(saved, sent):
            abort(400, description="Invalid form token. Refresh and try again.")

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        with connect_db() as con:
            user = con.execute(
                "SELECT role FROM users WHERE id=?",
                (session["user_id"],)
            ).fetchone()
        if not user or user["role"] != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def is_admin():
    if not session.get("user_id"):
        return False
    with connect_db() as con:
        user = con.execute(
            "SELECT role FROM users WHERE id=?",
            (session["user_id"],)
        ).fetchone()
    return bool(user and user["role"] == "admin")

def log_action(action, filename=""):
    with connect_db() as con:
        con.execute("""
        INSERT INTO activity(user_id,action,filename,created)
        VALUES(?,?,?,?)
        """, (
            session.get("user_id"), action, filename,
            datetime.now(timezone.utc).isoformat()
        ))

# ==================================================
# PAGE DESIGN
# ==================================================

PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<meta name="description" content="{{ description }}">
<meta name="robots" content="{{ robots }}">
{% if canonical %}<link rel="canonical" href="{{ canonical }}">{% endif %}
<meta name="theme-color" content="#071426">
<meta property="og:type" content="website">
<meta property="og:title" content="{{ title }}">
<meta property="og:description" content="{{ description }}">
{% if canonical %}<meta property="og:url" content="{{ canonical }}">{% endif %}
<style>
*{box-sizing:border-box}
body{margin:0;background:#071426;color:#fff;font-family:Arial,sans-serif}
header{background:#0c2039;border-bottom:2px solid #c49b4e;padding:20px 5%;
display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:15px}
.brand{font-size:22px;font-weight:bold;color:#e5bd68;text-decoration:none}
nav a{color:#fff;text-decoration:none;margin:8px}
main{max-width:1100px;margin:35px auto;padding:15px}
.card{background:#102641;border:1px solid #29415e;border-radius:14px;padding:24px;margin:15px 0}
h1,h2{color:#e5bd68}
input,select,button{width:100%;padding:13px;margin:8px 0;border-radius:7px;border:1px solid #49617c}
input,select{background:#071426;color:white}
button{background:#d5aa55;color:#111;font-weight:bold;cursor:pointer;border:0}
a{color:#e5bd68}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:15px}
.small{color:#bdc9d8;line-height:1.6}
footer{text-align:center;padding:25px;color:#bdc9d8}
table{border-collapse:collapse;width:100%;overflow-wrap:anywhere}
td,th{border:1px solid #49617c;padding:8px;text-align:left}
@media(max-width:600px){header{display:block}nav{margin-top:15px}nav a{margin:5px}}
</style>
</head>
<body>
<header>
<a class="brand" href="/">R | RAKSHIT FILE CONVERTER</a>
<nav>
<a href="/">Home</a>
{% if session.get('user_id') %}
<a href="/tools">Tools</a>
{% if admin %}<a href="/admin">Admin</a>{% endif %}
<a href="/logout">Logout</a>
{% else %}
<a href="/login">Login</a>
<a href="/register">Register</a>
{% endif %}
</nav>
</header>
<main>
{% with messages=get_flashed_messages() %}
{% for message in messages %}
<div class="card">{{ message }}</div>
{% endfor %}
{% endwith %}
{{ content|safe }}
</main>
<footer>© {{ year }} Rakshit File Converter. All rights reserved.</footer>
</body>
</html>
"""

def render_page(content, title="Rakshit File Converter",
                description="Convert and manage PDF and image files online with Rakshit File Converter.",
                public=False, **kwargs):
    canonical = (SITE_URL + request.path) if SITE_URL else ""
    rendered = render_template_string(content, **kwargs)
    return render_template_string(
        PAGE, content=rendered, title=title,
        description=description,
        robots="index,follow" if public else "noindex,nofollow",
        canonical=canonical,
        admin=is_admin(),
        year=datetime.now().year
    )

CSRF = '<input type="hidden" name="csrf" value="{{ csrf_token() }}">'

# ==================================================
# PUBLIC SEO ROUTES
# ==================================================

@app.route("/")
def home():
    return render_page("""
    <section class="card">
      <h1>Rakshit File Converter – Free Online PDF & Image Tools</h1>
      <p class="small">
      Welcome to Rakshit File Converter. Convert and manage PDF and image
      files with a simple, user-friendly online platform.
      </p>
      <p><a href="/register">Create your free account</a> or
      <a href="/login">sign in</a> to start using the tools.</p>
    </section>
    <div class="grid">
      <section class="card">
        <h2>PDF Tools</h2>
        <p>Merge, compress, rotate and watermark PDF documents.</p>
      </section>
      <section class="card">
        <h2>Image Tools</h2>
        <p>Convert images to PNG, JPEG and WEBP, and compress images.</p>
      </section>
      <section class="card">
        <h2>Simple and Secure Access</h2>
        <p>Sign in to use conversion tools and access your account.</p>
      </section>
    </div>
    <section class="card">
      <h2>How to use Rakshit File Converter</h2>
      <p>1. Create an account. 2. Sign in. 3. Choose a tool.
      4. Upload your file. 5. Download the converted result.</p>
    </section>
    """, title="Rakshit File Converter | Online PDF & Image Converter",
    description="Rakshit File Converter offers online PDF merging, compression, rotation, watermarking and image conversion tools.",
    public=True)

@app.route("/robots.txt")
def robots():
    base = SITE_URL or request.url_root.rstrip("/")
    body = f"""User-agent: *
Allow: /
Disallow: /admin
Disallow: /tools
Disallow: /login
Disallow: /register
Disallow: /logout
Disallow: /admin/export

Sitemap: {base}/sitemap.xml
"""
    return make_response(body, 200, {"Content-Type": "text/plain"})

@app.route("/sitemap.xml")
def sitemap():
    base = SITE_URL or request.url_root.rstrip("/")
    urls = ["/"]
    xml = '<?xml version="1.0" encoding="UTF-8"?>'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    for path in urls:
        xml += "<url><loc>" + escape(base + path) + "</loc></url>"
    xml += "</urlset>"
    return make_response(xml, 200, {"Content-Type": "application/xml"})

@app.route("/health")
def health():
    return {"status": "ok", "app": "Rakshit File Converter"}

# ==================================================
# ACCOUNT ROUTES
# ==================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or len(name) > 100:
            flash("Please enter a valid name.")
            return redirect(url_for("register"))
        if not re.fullmatch(r"[^@\\s]+@[^@\\s]+\\.[^@\\s]+", email):
            flash("Please enter a valid email.")
            return redirect(url_for("register"))
        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("register"))

        try:
            with connect_db() as con:
                con.execute("""
                INSERT INTO users(name,email,password,role,created)
                VALUES(?,?,?,?,?)
                """, (name, email, generate_password_hash(password),
                      "user", datetime.now(timezone.utc).isoformat()))
            flash("Account created. Please sign in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("This email is already registered.")

    return render_page("""
    <div class="card"><h1>Create Account</h1>
    <form method="post">""" + CSRF + """
    <input name="name" placeholder="Full name" maxlength="100" required>
    <input name="email" type="email" placeholder="Email address" required>
    <input name="password" type="password" minlength="8" placeholder="Password (8+ characters)" required>
    <button>Create Account</button>
    </form></div>
    """, title="Create Account | Rakshit File Converter")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with connect_db() as con:
            user = con.execute(
                "SELECT * FROM users WHERE email=?", (email,)
            ).fetchone()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["csrf"] = secrets.token_urlsafe(32)
            return redirect(url_for("tools"))
        flash("Incorrect email or password.")

    return render_page("""
    <div class="card"><h1>Sign In</h1>
    <form method="post">""" + CSRF + """
    <input name="email" type="email" placeholder="Email" required>
    <input name="password" type="password" placeholder="Password" required>
    <button>Sign In</button>
    </form></div>
    """, title="Sign In | Rakshit File Converter")

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("home"))

# ==================================================
# FILE HELPERS
# ==================================================

def upload_file(file):
    if not file or not file.filename:
        raise ValueError("Select a file first.")
    name = secure_filename(file.filename)
    if not name:
        raise ValueError("Invalid filename.")
    path = UPLOADS / (secrets.token_hex(16) + "_" + name)
    file.save(path)
    return path

def result_file(data, filename, mimetype):
    safe_name = secure_filename(filename)
    path = OUTPUTS / (secrets.token_hex(16) + "_" + safe_name)
    path.write_bytes(data)
    log_action("Converted file", safe_name)
    response = send_file(path, as_attachment=True,
                         download_name=safe_name, mimetype=mimetype)
    response.call_on_close(lambda: path.unlink(missing_ok=True))
    return response

# ==================================================
# TOOLS DASHBOARD
# ==================================================

@app.route("/tools")
@login_required
def tools():
    return render_page("""
    <h1>Welcome, {{ name }}</h1>
    <p class="small">Choose a conversion tool below.</p>
    <div class="grid">
    <div class="card"><h2>Merge PDF</h2>
    <form method="post" action="/merge" enctype="multipart/form-data">
    """ + CSRF + """
    <input type="file" name="files" accept=".pdf,application/pdf" multiple required>
    <button>Merge PDFs</button></form></div>

    <div class="card"><h2>Compress PDF</h2>
    <form method="post" action="/compress" enctype="multipart/form-data">
    """ + CSRF + """
    <input type="file" name="file" accept=".pdf,application/pdf" required>
    <button>Compress PDF</button></form></div>

    <div class="card"><h2>Rotate PDF</h2>
    <form method="post" action="/rotate" enctype="multipart/form-data">
    """ + CSRF + """
    <input type="file" name="file" accept=".pdf,application/pdf" required>
    <button>Rotate PDF 90°</button></form></div>

    <div class="card"><h2>Watermark PDF</h2>
    <form method="post" action="/watermark" enctype="multipart/form-data">
    """ + CSRF + """
    <input type="file" name="file" accept=".pdf,application/pdf" required>
    <input name="watermark" maxlength="100" placeholder="Watermark text" required>
    <button>Add Watermark</button></form></div>

    <div class="card"><h2>Convert Image</h2>
    <form method="post" action="/image" enctype="multipart/form-data">
    """ + CSRF + """
    <input type="file" name="file" accept="image/*" required>
    <select name="format"><option>PNG</option><option>JPEG</option><option>WEBP</option></select>
    <button>Convert Image</button></form></div>

    <div class="card"><h2>Compress Image</h2>
    <form method="post" action="/image-compress" enctype="multipart/form-data">
    """ + CSRF + """
    <input type="file" name="file" accept="image/*" required>
    <button>Compress Image</button></form></div>
    </div>
    """, title="Conversion Tools | Rakshit File Converter",
    name=session.get("name", "User"))

# ==================================================
# PDF ROUTES
# ==================================================

@app.route("/merge", methods=["POST"])
@login_required
def merge():
    files = request.files.getlist("files")
    if len(files) < 2:
        abort(400, description="Select at least two PDF files.")
    result = pymupdf.open()
    try:
        for file in files:
            path = upload_file(file)
            try:
                with pymupdf.open(path) as doc:
                    if doc.is_encrypted:
                        abort(400, description="Password-protected PDFs are not supported by this tool.")
                    result.insert_pdf(doc)
            finally:
                path.unlink(missing_ok=True)
        data = result.tobytes(garbage=3, deflate=True)
    finally:
        result.close()
    return result_file(data, "merged.pdf", "application/pdf")

@app.route("/compress", methods=["POST"])
@login_required
def compress():
    path = upload_file(request.files.get("file"))
    try:
        with pymupdf.open(path) as doc:
            if doc.is_encrypted:
                abort(400, description="Password-protected PDF is not supported.")
            data = doc.tobytes(garbage=4, deflate=True, clean=True)
    finally:
        path.unlink(missing_ok=True)
    return result_file(data, "compressed.pdf", "application/pdf")

@app.route("/rotate", methods=["POST"])
@login_required
def rotate():
    path = upload_file(request.files.get("file"))
    try:
        with pymupdf.open(path) as doc:
            if doc.is_encrypted:
                abort(400, description="Password-protected PDF is not supported.")
            for page in doc:
                page.set_rotation((page.rotation + 90) % 360)
            data = doc.tobytes()
    finally:
        path.unlink(missing_ok=True)
    return result_file(data, "rotated.pdf", "application/pdf")

@app.route("/watermark", methods=["POST"])
@login_required
def watermark():
    path = upload_file(request.files.get("file"))
    text = request.form.get("watermark", "").strip()[:100]
    if not text:
        path.unlink(missing_ok=True)
        abort(400, description="Enter watermark text.")
    try:
        with pymupdf.open(path) as doc:
            if doc.is_encrypted:
                abort(400, description="Password-protected PDF is not supported.")
            for page in doc:
                page.insert_text((60, 70), text, fontsize=20,
                                 color=(0.7, 0.5, 0.2), overlay=True)
            data = doc.tobytes()
    finally:
        path.unlink(missing_ok=True)
    return result_file(data, "watermarked.pdf", "application/pdf")

# ==================================================
# IMAGE ROUTES
# ==================================================

@app.route("/image", methods=["POST"])
@login_required
def image_convert():
    path = upload_file(request.files.get("file"))
    fmt = request.form.get("format", "PNG").upper()
    if fmt not in ("PNG", "JPEG", "WEBP"):
        path.unlink(missing_ok=True)
        abort(400, description="Unsupported image format.")
    try:
        with Image.open(path) as source:
            im = source.copy()
        if fmt == "JPEG":
            im = im.convert("RGB")
        output = io.BytesIO()
        im.save(output, format=fmt)
        data = output.getvalue()
    finally:
        path.unlink(missing_ok=True)
    ext = "jpg" if fmt == "JPEG" else fmt.lower()
    mime = "image/jpeg" if fmt == "JPEG" else "image/" + ext
    return result_file(data, "converted." + ext, mime)

@app.route("/image-compress", methods=["POST"])
@login_required
def image_compress():
    path = upload_file(request.files.get("file"))
    try:
        with Image.open(path) as source:
            im = source.convert("RGB")
        output = io.BytesIO()
        im.save(output, format="JPEG", quality=65, optimize=True)
        data = output.getvalue()
    finally:
        path.unlink(missing_ok=True)
    return result_file(data, "compressed.jpg", "image/jpeg")

# ==================================================
# ADMIN PANEL AND EXCEL
# ==================================================

@app.route("/admin")
@admin_required
def admin():
    with connect_db() as con:
        users = con.execute(
            "SELECT id,name,email,role,created FROM users ORDER BY id DESC"
        ).fetchall()
        activity = con.execute("""
        SELECT activity.user_id,activity.action,activity.filename,
               activity.created,users.email
        FROM activity LEFT JOIN users ON users.id=activity.user_id
        ORDER BY activity.id DESC LIMIT 100
        """).fetchall()

    user_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            u["id"], html.escape(u["name"]), html.escape(u["email"]),
            html.escape(u["role"])
        ) for u in users
    )
    activity_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            html.escape(a["email"] or "Unknown"),
            html.escape(a["action"] or ""),
            html.escape(a["created"] or "")
        ) for a in activity
    )

    return render_page("""
    <h1>Admin Dashboard</h1>
    <p><a href="/admin/export">Download Excel Report</a></p>
    <div class="card"><h2>Registered Users</h2>
    <table><tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th></tr>
    """ + user_rows + """
    </table></div>
    <div class="card"><h2>Recent Activity</h2>
    <table><tr><th>Email</th><th>Action</th><th>Date</th></tr>
    """ + activity_rows + """
    </table></div>
    """, title="Admin Dashboard | Rakshit File Converter")

@app.route("/admin/export")
@admin_required
def export():
    wb = Workbook()
    ws = wb.active
    ws.title = "Users"
    ws.append(["ID", "Name", "Email", "Role", "Created"])

    with connect_db() as con:
        for row in con.execute(
            "SELECT id,name,email,role,created FROM users"
        ):
            ws.append(list(row))

        logs = wb.create_sheet("Activity")
        logs.append(["User ID", "Action", "Filename", "Created"])
        for row in con.execute(
            "SELECT user_id,action,filename,created FROM activity"
        ):
            logs.append(list(row))

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return send_file(
        output, as_attachment=True,
        download_name="rakshit_file_converter_report.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

# ==================================================
# ERROR HANDLERS
# ==================================================

@app.errorhandler(400)
def bad_request(error):
    return render_page("""
    <div class="card"><h1>Bad Request</h1>
    <p>{{ message }}</p><a href="/">Return Home</a></div>
    """, title="Bad Request | Rakshit File Converter",
    message=getattr(error, "description", "Refresh and try again.")), 400

@app.errorhandler(403)
def forbidden(error):
    return render_page(
        "<div class='card'><h1>Access Denied</h1></div>",
        title="Access Denied"
    ), 403

@app.errorhandler(404)
def not_found(error):
    return render_page(
        "<div class='card'><h1>Page Not Found</h1><a href='/'>Home</a></div>",
        title="Page Not Found"
    ), 404

@app.errorhandler(413)
def too_large(error):
    return render_page(
        "<div class='card'><h1>File Too Large</h1><p>Maximum request size is 25 MB.</p></div>",
        title="File Too Large"
    ), 413

# ==================================================
# START
# ==================================================

if __name__ == "__main__":
    serve(app, host="127.0.0.1", port=5000, threads=4)
