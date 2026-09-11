"""
VulnShop - A deliberately vulnerable Flask e-commerce backend
================================================================
Built ONLY as an audit target for a secure-coding-review exercise.
DO NOT deploy this code. Every vulnerability here is intentional
and is catalogued in ../SECURITY_REVIEW_REPORT.md
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

from flask import Flask, request, render_template_string, redirect, make_response

app = Flask(__name__)

# ---------------------------------------------------------------------------
# VULN-01: Hardcoded secrets / credentials committed to source control
# ---------------------------------------------------------------------------
app.secret_key = "supersecret123"
DB_ADMIN_PASSWORD = "Admin@123"
STRIPE_API_KEY = "sk_live_51Hxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

DB_PATH = "shop.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, "
        "username TEXT, password TEXT, is_admin INTEGER DEFAULT 0)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password, is_admin) "
        "VALUES (1, 'admin', ?, 1)",
        (hashlib.md5(DB_ADMIN_PASSWORD.encode()).hexdigest(),),  # VULN-02: weak hash
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# VULN-02: Weak/broken cryptography for password storage (MD5, no salt)
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


# ---------------------------------------------------------------------------
# VULN-03: SQL Injection — user input concatenated directly into query
# ---------------------------------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    hashed = hash_password(password)

    query = (
        "SELECT id, is_admin FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + hashed
        + "'"
    )
    conn = get_db()
    cur = conn.execute(query)          # <-- string-built SQL, classic SQLi
    row = cur.fetchone()
    conn.close()

    if row:
        resp = make_response(f"Welcome {username}")
        # ------------------------------------------------------------------
        # VULN-04: Predictable session token (insecure randomness)
        # ------------------------------------------------------------------
        token = str(random.randint(100000, 999999))
        resp.set_cookie("session_token", token)   # VULN-05: no Secure/HttpOnly flags
        return resp
    return "Invalid credentials", 401


# ---------------------------------------------------------------------------
# VULN-06: Reflected Cross-Site Scripting (XSS) — unescaped template render
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    query = request.args.get("q", "")
    template = f"<h1>Search results for: {query}</h1>"
    return render_template_string(template)   # user input rendered raw


# ---------------------------------------------------------------------------
# VULN-07: OS Command Injection
# ---------------------------------------------------------------------------
@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.run(
        "ping -c 1 " + host, shell=True, capture_output=True, text=True  # shell=True + concat
    )
    return f"<pre>{result.stdout}</pre>"


# ---------------------------------------------------------------------------
# VULN-08: Path Traversal — unsanitized filename used to read local files
# ---------------------------------------------------------------------------
@app.route("/download")
def download():
    filename = request.args.get("file")
    path = os.path.join("uploads", filename)   # no normalization / allow-list
    with open(path, "rb") as f:
        return f.read()


# ---------------------------------------------------------------------------
# VULN-09: Insecure Deserialization — pickle.loads on untrusted input
# ---------------------------------------------------------------------------
@app.route("/cart", methods=["POST"])
def load_cart():
    raw = request.data
    cart = pickle.loads(raw)     # remote code execution risk
    return {"items": len(cart)}


# ---------------------------------------------------------------------------
# VULN-10: Server-Side Request Forgery (SSRF)
# ---------------------------------------------------------------------------
@app.route("/fetch-invoice")
def fetch_invoice():
    import urllib.request
    url = request.args.get("url")
    data = urllib.request.urlopen(url).read()   # attacker-controlled URL, no allow-list
    return data


# ---------------------------------------------------------------------------
# VULN-11: Open Redirect
# ---------------------------------------------------------------------------
@app.route("/go")
def go():
    next_url = request.args.get("next")
    return redirect(next_url)    # unvalidated redirect target


# ---------------------------------------------------------------------------
# VULN-12: Use of eval() on user-controlled input
# ---------------------------------------------------------------------------
@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    result = eval(expr)          # arbitrary code execution
    return str(result)


# ---------------------------------------------------------------------------
# VULN-13: Debug mode enabled in what looks like a prod entrypoint,
#          binding to all interfaces
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
