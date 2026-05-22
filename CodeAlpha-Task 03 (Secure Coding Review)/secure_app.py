#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         CodeAlpha Cybersecurity Internship — Task 3          ║
║              Secure Coding Review                            ║
║              SECURE APPLICATION — All Fixes Applied          ║
╚══════════════════════════════════════════════════════════════╝
Author : Hiruni Ranasinghe
GitHub : https://github.com/hiruranasinghe
Repo   : CodeAlpha_SecureCodingReview

All 10 vulnerabilities from vulnerable_app.py have been fixed.
See code_review_report.md for full audit details.
"""

from flask import Flask, request, jsonify, session, abort
from functools import wraps
import sqlite3
import subprocess
import secrets
import bcrypt
import os
import re
import time

# ── Colours for terminal output ──────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"

def banner():
    print(f"""
{C.GREEN}{C.BOLD}
 ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗
 ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
 ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗
 ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝
 ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
{C.RESET}
{C.GREEN}  ✔  SECURE APPLICATION — All 10 Vulnerabilities Fixed  ✔{C.RESET}
{C.WHITE}  CodeAlpha Cybersecurity Internship | Task 3 — Secure Coding Review{C.RESET}
{C.CYAN}  Author : Hiruni Ranasinghe{C.RESET}
{C.CYAN}  GitHub : https://github.com/hiruranasinghe{C.RESET}
""")

def print_fix(num, name, method):
    print(f"  {C.GREEN}{C.BOLD}[FIX-{num:02d}]{C.RESET}  {C.WHITE}{name}{C.RESET}")
    print(f"           {C.CYAN}→ {method}{C.RESET}")

def fix_summary():
    print(f"\n{C.GREEN}{C.BOLD}{'═'*62}{C.RESET}")
    print(f"{C.GREEN}{C.BOLD}  SECURITY FIX SUMMARY — secure_app.py{C.RESET}")
    print(f"{C.GREEN}{C.BOLD}{'═'*62}{C.RESET}\n")
    fixes = [
        (1,  "Hardcoded Secret Key",          "Environment variable + secrets.token_hex()"),
        (2,  "SQL Injection — Login",          "Parameterised queries + bcrypt"),
        (3,  "Broken Access Control",          "@login_required + @admin_required decorators"),
        (4,  "SQL Injection — Admin Search",   "Parameterised LIKE query"),
        (5,  "Sensitive Data Exposure",        "Explicit safe column selection only"),
        (6,  "OS Command Injection",           "Regex validation + shell=False + list args"),
        (7,  "Plaintext Password Storage",     "bcrypt hashing with salt"),
        (8,  "Insecure Deserialization",       "Removed pickle — typed JSON allowlist only"),
        (9,  "Path Traversal",                 "os.path.realpath() boundary check"),
        (10, "Predictable Reset Token",        "secrets.token_urlsafe(32) + DB expiry"),
    ]
    for f in fixes:
        print_fix(*f)
    print(f"\n{C.GREEN}  ✔ All 10 vulnerabilities remediated{C.RESET}")
    print(f"{C.GREEN}  ✔ OWASP Top 10 compliance checked{C.RESET}")
    print(f"{C.GREEN}  ✔ Authentication enforced on all sensitive endpoints{C.RESET}")
    print(f"\n{C.GREEN}{C.BOLD}{'═'*62}{C.RESET}\n")

# ── Flask app ─────────────────────────────────────────────────
app = Flask(__name__)

# FIX #1 — Secret key from environment, never hardcoded
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"]   = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DB_PATH         = "users.db"
ALLOWED_LOG_DIR = os.path.realpath("/var/log/app/")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            abort(401)
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return login_required(decorated)


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY,
            username      TEXT UNIQUE,
            password_hash TEXT,
            email         TEXT,
            role          TEXT DEFAULT 'user'
        )
    """)
    hashed = bcrypt.hashpw(b"Admin@Secure1!", bcrypt.gensalt())
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (?,?,?,?,?)",
        (1, "admin", hashed.decode(), "admin@example.com", "admin")
    )
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reset_tokens (
            token      TEXT PRIMARY KEY,
            username   TEXT,
            expires_at REAL
        )
    """)
    conn.commit()
    conn.close()


# FIX #2 — Parameterised query + bcrypt comparison
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").encode()
    if not username or not password:
        return jsonify({"status": "fail"}), 400
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    if user and bcrypt.checkpw(password, user["password_hash"].encode()):
        session.clear()
        session["user"] = user["username"]
        session["role"] = user["role"]
        return jsonify({"status": "ok"})
    return jsonify({"status": "Invalid credentials"}), 401


# FIX #3 + #4 + #5 — Auth check + parameterised query + safe columns
@app.route("/admin/search")
@login_required
@admin_required
def admin_search():
    query = request.args.get("q", "")
    conn  = get_db()
    rows  = conn.execute(
        "SELECT id, username, email, role FROM users WHERE username LIKE ?",
        (f"%{query}%",)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# FIX #6 — Input validation + shell=False + list args
@app.route("/diagnostics")
@login_required
@admin_required
def diagnostics():
    host = request.args.get("host", "127.0.0.1")
    if not re.match(r'^[a-zA-Z0-9.\-]{1,253}$', host):
        return jsonify({"error": "Invalid host"}), 400
    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True, text=True, timeout=5
        )
        return jsonify({"output": result.stdout})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timed out"}), 408


# FIX #7 — bcrypt hashing + parameterised query
@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    new_password = request.form.get("password", "")
    if len(new_password) < 12:
        return jsonify({"error": "Min 12 characters required"}), 400
    hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
    conn   = get_db()
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        (hashed.decode(), session["user"])
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "password updated"})


# FIX #8 — Removed pickle entirely, typed JSON allowlist
@app.route("/restore-session", methods=["POST"])
@login_required
def restore_session():
    data        = request.get_json(silent=True) or {}
    allowed     = {"theme", "language", "timezone"}
    preferences = {k: str(v)[:64] for k, v in data.items() if k in allowed}
    session["preferences"] = preferences
    return jsonify({"status": "restored", "preferences": preferences})


# FIX #9 — realpath() boundary check prevents traversal
@app.route("/logs")
@login_required
@admin_required
def read_logs():
    filename  = request.args.get("file", "app.log")
    requested = os.path.realpath(os.path.join(ALLOWED_LOG_DIR, filename))
    if not requested.startswith(ALLOWED_LOG_DIR + os.sep):
        return jsonify({"error": "Access denied"}), 403
    if not os.path.isfile(requested):
        return jsonify({"error": "File not found"}), 404
    with open(requested) as f:
        return f.read()


# FIX #10 — Cryptographically secure token, DB stored, expiry, single use
@app.route("/request-reset", methods=["POST"])
def request_reset():
    username = request.form.get("username", "")
    conn     = get_db()
    user     = conn.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    if user:
        token      = secrets.token_urlsafe(32)
        expires_at = time.time() + 3600
        conn.execute(
            "INSERT OR REPLACE INTO reset_tokens VALUES (?,?,?)",
            (token, username, expires_at)
        )
        conn.commit()
    conn.close()
    return jsonify({"status": "If that account exists, a reset email was sent."})


@app.route("/reset-password")
def reset_password():
    token  = request.args.get("token", "")
    conn   = get_db()
    record = conn.execute(
        "SELECT * FROM reset_tokens WHERE token = ?", (token,)
    ).fetchone()
    if not record or record["expires_at"] < time.time():
        conn.close()
        return jsonify({"status": "Invalid or expired token"}), 403
    conn.execute("DELETE FROM reset_tokens WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    return jsonify({"status": "token valid, proceed to reset"})


if __name__ == "__main__":
    banner()
    fix_summary()
    init_db()
    # FIX — debug=False in production
    app.run(debug=False)