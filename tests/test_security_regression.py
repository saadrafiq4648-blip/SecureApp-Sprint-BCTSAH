import ctypes
import subprocess
import pytest
from src.app import app, db, seed_demo_users

@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            seed_demo_users()
        yield client

def login(client, email, password):
    return client.post("/login", data={"email": email, "password": password})

def get_csrf_token(client):
    return client.get("/csrf-token").get_json()["csrf_token"]

def test_tc01_buffer_overflow_rejected():
    subprocess.run(["make", "-C", "native", "libmetaparse.so"], check=True)
    lib = ctypes.CDLL("./native/libmetaparse.so")
    lib.parse_header.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
    lib.parse_header.restype = ctypes.c_int
    class Manifest(ctypes.Structure):
        _fields_ = [("title", ctypes.c_char * 64), ("author", ctypes.c_char * 32)]
    m = Manifest()
    oversized = b"A" * 200
    assert lib.parse_header(oversized, len(oversized), ctypes.byref(m)) == -1
    valid = b"Quarterly Security Report"
    assert lib.parse_header(valid, len(valid), ctypes.byref(m)) == 0

def test_tc02_command_injection_rejected(client):
    login(client, "alice@secureshare.local", "AlicePass123!")
    token = get_csrf_token(client)
    resp = client.post("/upload", data={"title": "report; id; whoami #", "filename": "evil.txt"}, headers={"X-CSRFToken": token})
    assert resp.status_code == 400

def test_tc03_idor_cross_user_denied(client):
    login(client, "alice@secureshare.local", "AlicePass123!")
    token = get_csrf_token(client)
    assert client.get("/files/2/download").status_code == 404
    assert client.get("/files/2").status_code == 404
    assert client.post("/files/2/convert", headers={"X-CSRFToken": token}).status_code == 404

def test_tc04_csrf_enforced_and_samesite_cookie(client):
    login_resp = login(client, "alice@secureshare.local", "AlicePass123!")
    assert "SameSite=Lax" in login_resp.headers.get("Set-Cookie", "")
    assert client.post("/files/1/share", data={"recipient": "attacker@evil.com"}).status_code == 400
    token = get_csrf_token(client)
    assert client.post("/files/1/share", data={"recipient": "colleague@secureshare.local"}, headers={"X-CSRFToken": token}).status_code == 200

def test_tc05_clickjacking_headers_present(client):
    login(client, "alice@secureshare.local", "AlicePass123!")
    resp = client.get("/files/1")
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in resp.headers.get("Content-Security-Policy", "")
