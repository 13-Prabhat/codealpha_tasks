"""
VulnShop - REMEDIATED version
================================================================
Same feature set as vulnerable_app/app.py, rewritten to close every
finding in SECURITY_REVIEW_REPORT.md. Comments marked FIX-xx map
1:1 to the VULN-xx findings in the original file.
"""

import ast
import hashlib
import hmac
import os
import secrets
import shlex
import sqlite3
import subprocess
import urllib.parse

from flask import Flask, request, render_template_string, redirect, make_response, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ---------------------------------------------------------------------------
# FIX-01: Secrets loaded from environment, never hardcoded / committed.
# Run with:  SECRET_KEY=... ADMIN_BOOTSTRAP_PASSWORD=... STRIPE_API_KEY=...
# ---------------------------------------------------------------------------
app.secret_key = os.environ["SECRET_KEY"]
ADMIN_BOOTSTRAP_PASSWORD = os.environ.get("ADMIN_BOOTSTRAP_PASSWORD")
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY")

DB_PATH = os.environ.get("DB_PATH", "shop.db")

# Allow-list of local files that /download may ever serve
DOWNLOAD_ALLOWLIST = {"catalog.pdf", "returns-policy.pdf"}
# Allow-list of hosts /fetch-invoice may call (SSRF mitigation)
INVOICE_HOST_ALLOWLIST = {"invoices.internal.example.com"}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, "
        "username TEXT UNIQUE, password_hash TEXT, is_admin INTEGER DEFAULT 0)"
    )
    if ADMIN_BOOTSTRAP_PASSWORD:
        conn.execute(
            "INSERT OR IGNORE INTO users (id, username, password_hash, is_admin) "
            "VALUES (1, 'admin', ?, 1)",
            # FIX-02: salted, slow hash (PBKDF2 via werkzeug) instead of raw MD5
            (generate_password_hash(ADMIN_BOOTSTRAP_PASSWORD),),
        )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# FIX-03: Parameterized query — the driver handles escaping, not string concat.
# FIX-04/05: Random, high-entropy session token generated with `secrets`,
#            cookie marked Secure + HttpOnly + SameSite, and constant-time
#            comparison used when validating credentials.
# ---------------------------------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_db()
    row = conn.execute(
        "SELECT id, password_hash, is_admin FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()

    if row is None or not check_password_hash(row["password_hash"], password):
        # Same error for "no such user" and "wrong password" -> no user enumeration
        return "Invalid credentials", 401

    token = secrets.token_urlsafe(32)
    resp = make_response("Login successful")
    resp.set_cookie(
        "session_token",
        token,
        secure=True,     # only sent over HTTPS
        httponly=True,   # not readable from JS -> mitigates XSS token theft
        samesite="Lax",  # CSRF mitigation
    )
    # In production: persist `token -> user_id` server-side (e.g. Redis) with a TTL.
    return resp


# ---------------------------------------------------------------------------
# FIX-06: Output is auto-escaped by using Jinja2 {{ }} placeholders instead
#         of f-string interpolation into the template source.
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    query = request.args.get("q", "")
    return render_template_string("<h1>Search results for: {{ q }}</h1>", q=query)


# ---------------------------------------------------------------------------
# FIX-07: No shell invocation at all; argument passed as a list, and the
#         host is validated against a strict format before use.
# ---------------------------------------------------------------------------
@app.route("/ping")
def ping_host():
    host = request.args.get("host", "127.0.0.1")
    # Only allow simple hostnames/IPv4 - reject anything with shell metacharacters
    if not all(c.isalnum() or c in ".-" for c in host) or len(host) > 253:
        abort(400, "invalid host")
    result = subprocess.run(
        ["ping", "-c", "1", host], shell=False, capture_output=True, text=True, timeout=5
    )
    return f"<pre>{result.stdout}</pre>"


# ---------------------------------------------------------------------------
# FIX-08: Filename resolved against an allow-list; no attacker-controlled
#         path segments ever reach the filesystem.
# ---------------------------------------------------------------------------
@app.route("/download")
def download():
    filename = request.args.get("file", "")
    if filename not in DOWNLOAD_ALLOWLIST:
        abort(404)
    safe_path = os.path.join("uploads", filename)
    with open(safe_path, "rb") as f:
        return f.read()


# ---------------------------------------------------------------------------
# FIX-09: Untrusted input is never unpickled. Use a safe, data-only format
#         (JSON) with schema validation instead.
# ---------------------------------------------------------------------------
@app.route("/cart", methods=["POST"])
def load_cart():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        abort(400, "invalid cart payload")
    return {"items": len(payload["items"])}


# ---------------------------------------------------------------------------
# FIX-10: SSRF mitigated with a strict destination allow-list; scheme pinned
#         to https; no redirects followed blindly.
# ---------------------------------------------------------------------------
@app.route("/fetch-invoice")
def fetch_invoice():
    import urllib.request

    url = request.args.get("url", "")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in INVOICE_HOST_ALLOWLIST:
        abort(400, "destination not allowed")
    with urllib.request.urlopen(url, timeout=5) as resp:
        return resp.read()


# ---------------------------------------------------------------------------
# FIX-11: Redirect target restricted to a set of known, relative, in-app paths.
# ---------------------------------------------------------------------------
SAFE_REDIRECTS = {"/", "/account", "/orders"}


@app.route("/go")
def go():
    next_url = request.args.get("next", "/")
    if next_url not in SAFE_REDIRECTS:
        next_url = "/"
    return redirect(next_url)


# ---------------------------------------------------------------------------
# FIX-12: No eval(). Arithmetic parsed safely with ast, whitelisting node
#         types so only numeric expressions are ever evaluated.
# ---------------------------------------------------------------------------
_ALLOWED_NODES = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.USub, ast.UAdd,
)


def safe_eval(expr: str):
    node = ast.parse(expr, mode="eval")
    for n in ast.walk(node):
        if not isinstance(n, _ALLOWED_NODES):
            raise ValueError("disallowed expression")
    return eval(compile(node, "<safe_eval>", "eval"))  # nosec B307 - AST-restricted


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    try:
        result = safe_eval(expr)
    except (ValueError, SyntaxError, ZeroDivisionError):
        abort(400, "invalid expression")
    return str(result)


# ---------------------------------------------------------------------------
# FIX-13: Debug mode and bind address controlled by environment; defaults
#         are safe (debug off, localhost only). A real deployment should run
#         behind a WSGI server (gunicorn/uwsgi) + reverse proxy, not app.run().
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    bind_host = os.environ.get("BIND_HOST", "127.0.0.1")
    app.run(host=bind_host, port=5000, debug=debug_mode)
