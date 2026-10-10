"""NoteVault — intentionally vulnerable helpdesk notes portal (lab).

Dual-mode app:
  SECURE=0 (default) — vulnerable build, served on :5000
  SECURE=1           — patched build, served on :5001

Run with: python app.py  (reads PORT and SECURE from env)
"""
import ipaddress
import os
import socket
import sqlite3
from functools import wraps
from urllib.parse import urlparse

import requests
from flask import (
    Flask, g, jsonify, redirect, render_template, request, session, url_for,
)

SECURE = os.environ.get("SECURE", "0") == "1"
DB_PATH = os.environ.get("DB_PATH", "/tmp/notevault.db")
PORT = int(os.environ.get("PORT", "5000"))

app = Flask(__name__)
# VULN (auth weakness, hardening): hardcoded dev secret. Anybody who reads
# the source (or brute-forces the default) can forge session cookies.
# Secure mode requires a real secret from the environment.
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
if SECURE and app.secret_key == "dev-secret-change-me":
    # Fail loudly rather than run "secure" with a public key.
    raise RuntimeError("SECURE=1 requires SECRET_KEY env var to be set")

FLAG = "flag{ssrf-reached-internal-admin}"


# ---------------------------------------------------------------- db ------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = db()
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        private_note TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE tickets (
        id INTEGER PRIMARY KEY,
        owner_id INTEGER NOT NULL REFERENCES users(id),
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        is_private INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE comments (
        id INTEGER PRIMARY KEY,
        ticket_id INTEGER NOT NULL REFERENCES tickets(id),
        author TEXT NOT NULL,
        body TEXT NOT NULL
    );
    """)
    # Passwords are plaintext on purpose in the lab's vulnerable build so the
    # SQL-injection login bypass reads naturally. Secure mode still accepts
    # these seeds (see REMEDIATION.md for what production must do instead:
    # per-user salted hashes, never plaintext).
    c.executemany(
        "INSERT INTO users (id, username, password, email, role, private_note)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        [
            (1, "alice", "alice123", "alice@example.com", "user",
             "Alice HR file: salary 92k, SSN 078-05-1120 (demo data)"),
            (2, "bob", "bob123", "bob@example.com", "user",
             "Bob medical file: accommodation request, doctor note (demo)"),
            (3, "admin", "admin123", "admin@example.com", "admin",
             "Rotation runbook: prod db password is Demo-Only-Rotate-Me"),
        ],
    )
    c.executemany(
        "INSERT INTO tickets (id, owner_id, title, body, is_private)"
        " VALUES (?, ?, ?, ?, ?)",
        [
            (1, 1, "Q3 performance bonus letter",
             "My bonus letter and payout details. Private to alice.", 1),
            (2, 2, "Medical accommodation request",
             "Doctor note and accommodation details. Private to bob.", 1),
            (3, 3, "Production DB credentials rotation",
             "Runbook and current rotation secret Demo-Only-Rotate-Me. Admins only.", 1),
            (4, 1, "Office wifi password",
             "Guest wifi password is Guest-Wifi-Demo. Shared with everyone.", 0),
        ],
    )
    c.executemany(
        "INSERT INTO comments (ticket_id, author, body) VALUES (?, ?, ?)",
        [
            (4, "alice", "This one is shared — feel free to reply here."),
        ],
    )
    conn.commit()
    conn.close()


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    conn = db()
    row = conn.execute("SELECT id, username, email, role FROM users WHERE id = ?",
                       (uid,)).fetchone()
    conn.close()
    return dict(row) if row else None


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not current_user():
            return redirect(url_for("login_page"))
        return fn(*a, **kw)
    return wrapper


def api_login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not current_user():
            return jsonify({"error": "authentication required"}), 401
        return fn(*a, **kw)
    return wrapper


# -------------------------------------------------------------- pages ------
@app.get("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login_page"))


@app.get("/login")
def login_page():
    return render_template("login.html", secure=SECURE)


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = db()
    if SECURE:
        row = conn.execute(
            "SELECT id, username FROM users WHERE username = ? AND password = ?",
            (username, password)).fetchone()
    else:
        # VULN 1 (SQL injection): credentials interpolated into the query.
        # Input breaks out of the string literal and rewrites query logic.
        query = ("SELECT id, username FROM users WHERE username = '%s'"
                 " AND password = '%s'" % (username, password))
        try:
            row = conn.execute(query).fetchone()
        except sqlite3.Error as e:
            conn.close()
            # VULN (info disclosure): raw DB error + offending query leak
            # schema details to the attacker. Secure mode hides both.
            return f"Database error: {e}<br><pre>{query}</pre>", 500
    conn.close()
    if row:
        session["uid"] = row["id"]
        return redirect(url_for("dashboard"))
    # VULN (user enumeration): distinct messages tell an attacker which
    # half of the credential pair was wrong. Secure mode uses one message.
    if SECURE:
        return render_template("login.html", error="Invalid credentials",
                               secure=True), 401
    return render_template("login.html", error="Unknown user" if not
                           _user_exists(username) else "Wrong password",
                           secure=False), 401


def _user_exists(username):
    conn = db()
    try:
        r = conn.execute("SELECT id FROM users WHERE username = '%s'" % username
                         ).fetchone()
    except sqlite3.Error:
        r = None
    conn.close()
    return r is not None


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.get("/dashboard")
@login_required
def dashboard():
    user = current_user()
    q = request.args.get("q", "")
    conn = db()
    if q:
        if SECURE:
            rows = conn.execute(
                "SELECT id, title, body FROM tickets"
                " WHERE (owner_id = ? OR is_private = 0)"
                " AND title LIKE ?",
                (user["id"], "%" + q + "%")).fetchall()
        else:
            # VULN 1 (SQL injection, search): same interpolation pattern.
            # Note the access-control side effect: this query has no
            # owner/private filter at all, so injection aside, search
            # already leaks other users' private tickets (see VULN 2).
            query = ("SELECT id, title, body FROM tickets WHERE title LIKE"
                     " '%%%s%%'" % q)
            try:
                rows = conn.execute(query).fetchall()
            except sqlite3.Error as e:
                conn.close()
                return f"Database error: {e}<br><pre>{query}</pre>", 500
    else:
        rows = conn.execute(
            "SELECT id, title, body FROM tickets WHERE owner_id = ? OR is_private = 0",
            (user["id"],)).fetchall()
    mine = conn.execute("SELECT id, title FROM tickets WHERE owner_id = ?",
                        (user["id"],)).fetchall()
    conn.close()
    return render_template("dashboard.html", user=user, tickets=list(rows),
                           mine=list(mine), q=q, secure=SECURE)


@app.get("/ticket/<int:tid>")
@login_required
def ticket_page(tid):
    user = current_user()
    conn = db()
    t = conn.execute("SELECT * FROM tickets WHERE id = ?", (tid,)).fetchone()
    if not t:
        conn.close()
        return "Not found", 404
    if SECURE and t["owner_id"] != user["id"] and t["is_private"] and user["role"] != "admin":
        conn.close()
        return "Forbidden", 403
    comments = conn.execute("SELECT author, body FROM comments WHERE ticket_id = ?"
                            " ORDER BY id", (tid,)).fetchall()
    conn.close()
    return render_template("ticket.html", user=user, ticket=dict(t),
                           comments=[dict(r) for r in comments], secure=SECURE)


@app.get("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user(), secure=SECURE)


# ---------------------------------------------------------------- API ------
@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "secure": SECURE})


@app.get("/api/search")
@api_login_required
def api_search():
    """JSON version of dashboard search — the canonical SQLi target."""
    q = request.args.get("q", "")
    conn = db()
    if SECURE:
        rows = conn.execute(
            "SELECT id, title, body FROM tickets WHERE title LIKE ?",
            ("%" + q + "%",)).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    # VULN 1: string-interpolated LIKE. Classic UNION-based extraction.
    query = "SELECT id, title, body FROM tickets WHERE title LIKE '%%%s%%'" % q
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.Error as e:
        conn.close()
        return jsonify({"error": str(e), "query": query}), 500
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.get("/api/tickets/<int:tid>")
@api_login_required
def api_ticket(tid):
    """VULN 2 (IDOR / broken access control): no ownership check."""
    user = current_user()
    conn = db()
    t = conn.execute("SELECT * FROM tickets WHERE id = ?", (tid,)).fetchone()
    conn.close()
    if not t:
        return jsonify({"error": "not found"}), 404
    if SECURE:
        t = dict(t)
        if t["owner_id"] != user["id"] and t["is_private"] and user["role"] != "admin":
            return jsonify({"error": "forbidden"}), 403
        return jsonify(t)
    return jsonify(dict(t))


@app.get("/api/users/<int:uid>")
@api_login_required
def api_user(uid):
    """VULN 2b (IDOR): any authenticated user can read anyone's record,
    including the private_note field."""
    conn = db()
    r = conn.execute("SELECT id, username, email, role, private_note FROM users"
                     " WHERE id = ?", (uid,)).fetchone()
    conn.close()
    if not r:
        return jsonify({"error": "not found"}), 404
    if SECURE:
        me = current_user()
        if me["id"] != r["id"] and me["role"] != "admin":
            return jsonify({"error": "forbidden"}), 403
    return jsonify(dict(r))


@app.post("/api/tickets/<int:tid>/comments")
@api_login_required
def api_comment(tid):
    """VULN 3 (stored XSS): comment body stored raw and rendered with |safe."""
    user = current_user()
    data = request.get_json(force=True, silent=True) or {}
    body = data.get("body", "")
    if not body:
        return jsonify({"error": "body required"}), 400
    conn = db()
    if not conn.execute("SELECT id FROM tickets WHERE id = ?", (tid,)).fetchone():
        conn.close()
        return jsonify({"error": "not found"}), 404
    conn.execute("INSERT INTO comments (ticket_id, author, body) VALUES (?, ?, ?)",
                 (tid, user["username"], body))
    conn.commit()
    cid = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    conn.close()
    return jsonify({"id": cid, "author": user["username"], "body": body})


def _is_public_url(url):
    """Secure-mode SSRF guard: allow http(s), resolve host, reject
    loopback / private / link-local / reserved addresses. No redirects."""
    try:
        p = urlparse(url)
    except ValueError:
        return False, "bad url"
    if p.scheme not in ("http", "https"):
        return False, "only http(s) allowed"
    host = p.hostname
    if not host:
        return False, "bad host"
    try:
        infos = socket.getaddrinfo(host, p.port or 80, family=socket.AF_UNSPEC,
                                   type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False, "dns failed"
    for fam, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        addr = ipaddress.ip_address(ip)
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified):
            return False, f"blocked target {ip}"
        # Explicit cloud-metadata block (defence in depth; link-local
        # check already covers it).
        if ip == "169.254.169.254":
            return False, "blocked metadata"
    return True, ""


@app.post("/api/avatar/fetch")
@api_login_required
def avatar_fetch():
    """VULN 4 (SSRF): fetches any URL the caller supplies and returns a
    slice of the response. Follows redirects, no allowlist, no IP check —
    so an attacker can make the server request its own internal endpoints
    (e.g. http://127.0.0.1:5000/internal/secret)."""
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "url required"}), 400
    if SECURE:
        ok, reason = _is_public_url(url)
        if not ok:
            return jsonify({"error": f"blocked: {reason}"}), 400
        try:
            r = requests.get(url, timeout=3, allow_redirects=False)
        except requests.RequestException as e:
            return jsonify({"error": f"fetch failed: {e}"}), 502
        return jsonify({"url": url, "status": r.status_code,
                        "preview": r.text[:500]})
    try:
        r = requests.get(url, timeout=3)
    except requests.RequestException as e:
        return jsonify({"error": f"fetch failed: {e}"}), 502
    return jsonify({"url": url, "status": r.status_code,
                    "preview": r.text[:2000]})


@app.get("/internal/secret")
def internal_secret():
    """Simulates an internal-only endpoint (cloud metadata / admin sidecar).
    In production this would be firewalled to localhost. The lab leaves it
    reachable so SSRF has something to prove itself against — the vuln is
    the fetcher, not this route. Secure mode still blocks the fetch."""
    return jsonify({"internal_only": True, "secret": FLAG,
                    "note": "pretend this is 169.254.169.254/latest/meta-data"})


# Debug endpoint: only enabled in vulnerable mode, mimics a forgotten
# framework debug/API-docs route leaking config.
@app.get("/api/debug")
def api_debug():
    if SECURE:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "db": DB_PATH, "secure": False,
        "secret_key_hint": app.secret_key[:3] + "...",
        "routes": [str(r) for r in app.url_map.iter_rules()],
    })


@app.after_request
def _headers(resp):
    # VULN (hardening): permissive CORS + no XSS/clickjacking headers.
    if not SECURE:
        resp.headers["Access-Control-Allow-Origin"] = "*"
    else:
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
    return resp


if __name__ == "__main__":
    init_db()
    print(f"NoteVault starting (SECURE={int(SECURE)}) on :{PORT}, db={DB_PATH}")
    app.run(host="0.0.0.0", port=PORT)
