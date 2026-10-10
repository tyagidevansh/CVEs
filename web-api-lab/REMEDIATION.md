# Detection & Remediation — NoteVault

For each vulnerability: how to spot it (black-box and in code), and the
fix as implemented in `SECURE=1` mode. Line references are to `app.py`.

## V1 — SQL injection (`login`, `api_search`, `dashboard`)

- **Attack Flow →** quote probe errors → UNION extraction / login bypass
  (see `README.md` Task 3).
- **Root Cause →** `%`-formatting user input into SQL strings.
  ```python
  # VULN
  query = "SELECT ... WHERE username = '%s' AND password = '%s'" % (u, p)
  conn.execute(query)
  ```
- **Impact →** arbitrary table reads through search; full authentication
  bypass through login; schema mapping via `sqlite_master`.
- **Detection →** black-box: `'` returns DB error text plus the echoed
  query. Code review: any `execute(f"…")` / `%` / `+` building SQL, any
  error handler returning exception strings or query text. DAST: time/UNION
  probes change row counts. Logging: 500s on `/api/search` with quote
  characters are the signature.
- **Secure Fix →** bound parameters, one generic message, no echo:
  ```python
  # SECURE
  row = conn.execute(
      "SELECT id, username FROM users WHERE username = ? AND password = ?",
      (username, password)).fetchone()
  ```
  Production further: salted password hashes (never plaintext), least-priv
  DB user, WAF as backstop only — never the fix.

## V2 — IDOR / Broken Access Control (`api_ticket`, `api_user`)

- **Attack Flow →** login as alice → `GET /api/tickets/2` → bob's private
  ticket, `200` (see Task 2).
- **Root Cause →** handler authorizes the session but never the object:
  ```python
  # VULN
  t = conn.execute("SELECT * FROM tickets WHERE id = ?", (tid,)).fetchone()
  return jsonify(dict(t))   # no owner check
  ```
- **Impact →** any authenticated user reads every private ticket, every
  `private_note`, the admin runbook — confidentiality collapse.
- **Detection →** black-box: sequential ids return other users' objects
  with `200`; compare `owner_id` in responses to your own id. Code review:
  any `WHERE id = ?` without `AND owner_id = ?` (or role check). Look for
  the pattern on nested routes too (`/comments`, bulk paths).
- **Secure Fix →** per-object, per-request enforcement:
  ```python
  # SECURE
  if t["owner_id"] != user["id"] and t["is_private"] and user["role"] != "admin":
      return jsonify({"error": "forbidden"}), 403
  ```
  Production further: centralize in an authorization helper/decorator (this
  lab inlines it for readability — note that as tech debt), deny by
  default, test with horizontal (alice→bob) and vertical (user→admin) cases.

## V3 — Stored XSS (`api_comment` + `ticket.html`)

- **Attack Flow →** POST `<script>` comment → reload ticket → executes as
  viewer (see Task 4).
- **Root Cause →** raw storage plus explicit unescaping at render:
  ```html
  {{ c.body|safe }}
  ```
  `|safe` tells Jinja "this is trusted markup" — it is not.
- **Impact →** script runs as every future reader; on admin-read tickets
  that means admin session theft and actions-as-admin. Proof-of-concept is
  an alert; real payloads exfiltrate cookies/tokens or forge requests.
- **Detection →** black-box: post unique marker (`XSS-PROBE-<n>`), check
  whether response HTML contains it verbatim vs entity-encoded; confirm
  with a benign `<script>alert(document.domain)</script>`. Code review:
  `|safe` on user data, `innerHTML` sinks, missing CSP. Note storage is
  identical in both modes — the bug is at the sink, which is why
  input-filters alone mislead.
- **Secure Fix →** default autoescape at render plus CSP:
  ```html
  {{ c.body }}
  ```
  ```python
  resp.headers["Content-Security-Policy"] = "default-src 'self'"
  ```
  Production further: context-appropriate encoding (HTML/attr/JS), CSP
  `script-src` without `unsafe-inline`, sanitize rich-HTML with an
  allowlist library if markup is a feature — never a blocklist regex.

## V4 — SSRF (`avatar_fetch` → `/internal/secret`)

- **Attack Flow →** POST `{"url": "http://127.0.0.1:5000/internal/secret"}`
  → server fetches it → flag in `preview` (see Task 5).
- **Root Cause →** `requests.get(url)` on attacker-supplied URL: any host,
  redirects followed, response returned:
  ```python
  # VULN
  r = requests.get(url, timeout=3)
  ```
- **Impact →** read of internal-only endpoints (here a metadata stand-in;
  in cloud: instance credentials, sidecars, localhost admin ports); blind
  network mapping via error oracle; protocol-dependent escalation.
- **Detection →** black-box: fetch a collaborator/unique URL and watch for
  the inbound hit (proves server-side fetch); then internal targets for
  content or timing/error differences. Code review: any server-side fetch
  of user-supplied URLs without scheme/host/resolved-IP checks.
- **Secure Fix →** resolve, then constrain (`_is_public_url`):
  ```python
  # SECURE (sketch)
  ok, reason = _is_public_url(url)   # http(s); DNS → reject private/
  if not ok:                         # loopback/link-local/reserved
      return 400
  requests.get(url, timeout=3, allow_redirects=False)
  ```
  Production further: explicit host allowlist (not just blocklist),
  egress firewalling, metadata-service protections (IMDSv2 / hop limits),
  no response-body reflection, per-feature timeouts.

## Hardening (bonus findings, Task 6)

| issue | detection | fix in secure mode |
|---|---|---|
| hardcoded Flask `secret_key` → cookie forgery | `/api/debug` hint; key in source | `SECRET_KEY` from env; refuse to boot without it |
| login oracle (`Unknown user` / `Wrong password`) | two bad logins, compare messages | single `Invalid credentials` |
| debug route + verbose SQL errors | `/api/debug` 200; quote → query echo | debug route `404`; generic errors |
| `Access-Control-Allow-Origin: *` | response headers | removed; `nosniff` / `DENY` / CSP set |

## Verification checklist

`bash tests/verify.sh` asserts: IDOR `403`s, UNION `[]`, login-bypass
`401`, XSS escaped, SSRF `400`, debug `404` — and that legitimate search,
commenting, and public-URL fetch still work on `:5001`. A fix that breaks
the feature fails the checklist by design.
