import os
import re
import secrets
import tempfile
import subprocess  # nosec B404
from flask import Flask, request, render_template_string, send_file, abort, jsonify
from flask_login import LoginManager, login_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import generate_password_hash, check_password_hash, safe_join
from src.models import db, User, File, Share
from src.auth.authorize import authorize

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///secureshare.db")
app.config["UPLOAD_FOLDER"] = os.path.join(tempfile.gettempdir(), "secureshare_uploads")
app.config["OUT_DIR"] = os.path.join(tempfile.gettempdir(), "secureshare_out")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
)

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["OUT_DIR"], exist_ok=True)

db.init_app(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

SAFE_TITLE = re.compile(r"^[A-Za-z0-9 _\-]{1,64}$")
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9_\-]+\.[A-Za-z0-9]{1,8}$")

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.after_request
def security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "frame-ancestors 'none'; default-src 'self'; script-src 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

@app.route("/csrf-token", methods=["GET"])
def get_csrf():
    return jsonify({"csrf_token": generate_csrf()})

@app.route("/login", methods=["GET", "POST"])
@csrf.exempt
def login():
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return jsonify({"status": "logged_in", "user_id": user.id, "email": user.email})
        return jsonify({"error": "Invalid credentials"}), 401
    return "<h2>SecureShare Login</h2>"

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    title = request.form.get("title", "Untitled")
    if not SAFE_TITLE.fullmatch(title):
        abort(400)
    filename = request.form.get("filename", f"file_{current_user.id}.txt")
    if not SAFE_FILENAME.fullmatch(filename):
        abort(400)
    filepath = safe_join(app.config["UPLOAD_FOLDER"], filename)
    if not filepath:
        abort(400)
    with open(filepath, "w") as fp:
        fp.write(request.form.get("content", "Sample content"))
    f = File(owner_id=current_user.id, title=title, original_name=filename, path=filepath)
    db.session.add(f)
    db.session.commit()
    return jsonify({"file_id": f.id, "title": f.title, "owner": current_user.email}), 201

@app.route("/files/<int:fid>/download", methods=["GET"])
@login_required
def download(fid):
    f = db.session.get(File, fid) or abort(404)
    authorize(current_user, f, "read")
    return send_file(f.path, download_name=f.original_name)

@app.route("/files/<int:fid>/convert", methods=["POST"])
@login_required
def convert(fid):
    f = db.session.get(File, fid) or abort(404)
    authorize(current_user, f, "read")
    if not SAFE_TITLE.fullmatch(f.title):
        abort(400)
    out_path = safe_join(app.config["OUT_DIR"], f"{f.id}.pdf")
    if not out_path:
        abort(400)
    subprocess.run(["/bin/cp", f.path, out_path], check=True, timeout=30, shell=False)  # nosec B603
    return jsonify({"status": "converted", "file_id": f.id, "out_path": out_path}), 200

@app.route("/files/<int:fid>/share", methods=["POST"])
@login_required
def share_file(fid):
    f = db.session.get(File, fid) or abort(404)
    authorize(current_user, f, "write")
    recipient = request.form.get("recipient", "")
    s = Share(file_id=f.id, recipient_email=recipient, permission="read")
    db.session.add(s)
    db.session.commit()
    return jsonify({"status": "shared", "file_id": f.id, "shared_with": recipient}), 200

@app.route("/files/<int:fid>", methods=["GET"])
@login_required
def preview_file(fid):
    f = db.session.get(File, fid) or abort(404)
    authorize(current_user, f, "read")
    shares = [s.recipient_email for s in f.shares]
    template = """<!DOCTYPE html><html><body>
      <h2>File Preview: {{ title }}</h2>
      <p>Currently Shared With: {{ shares_str }}</p>
    </body></html>"""
    return render_template_string(template, title=f.title, shares_str=", ".join(shares) if shares else "Nobody")

def seed_demo_users():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email="alice@secureshare.local").first():
            u1 = User(email="alice@secureshare.local", password_hash=generate_password_hash("AlicePass123!"))
            u2 = User(email="bob@secureshare.local", password_hash=generate_password_hash("BobPass123!"))
            db.session.add_all([u1, u2])
            db.session.commit()
            p1 = os.path.join(app.config["UPLOAD_FOLDER"], "alice_notes.txt")
            p2 = os.path.join(app.config["UPLOAD_FOLDER"], "bob_confidential_salary.txt")
            with open(p1, "w") as fp: fp.write("Alice personal notes.\n")
            with open(p2, "w") as fp: fp.write("CONFIDENTIAL: Bob Salary = $145,000, SSN = 999-00-1234\n")
            f1 = File(owner_id=u1.id, title="Alice Notes", original_name="alice_notes.txt", path=p1)
            f2 = File(owner_id=u2.id, title="Bob Secret Salary", original_name="bob_confidential_salary.txt", path=p2)
            db.session.add_all([f1, f2])
            db.session.commit()

if __name__ == "__main__":
    seed_demo_users()
    app.run(host=os.environ.get("FLASK_HOST", "127.0.0.1"), port=5000, debug=False)
