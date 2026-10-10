# Architecture & Attack Flows — NoteVault

## Topology

```
                    ┌────────────────────────────────────────────┐
                    │              Docker host                    │
                    │                                            │
  student ────────► │  vulnerable :5000   secure :5001 (ref)     │
  browser + curl    │  ┌────────────────┐ ┌────────────────┐     │
                    │  │ Flask (SECURE │ │ Flask (SECURE  │     │
                    │  │ =0)           │ │ =1)            │     │
                    │  │  ├─ pages     │ │  (same routes, │     │
                    │  │  ├─ /api/*    │ │   guards on)   │     │
                    │  │  └─ /internal │ │                │     │
                    │  │     /secret   │ │                │     │
                    │  │  SQLite seed: │ │  SQLite seed   │     │
                    │  │  alice/bob/   │ │  (same)        │     │
                    │  │  admin, 4     │ │                │     │
                    │  │  tickets      │ │                │     │
                    │  └────────────────┘ └────────────────┘     │
                    └────────────────────────────────────────────┘
```

One codebase, two modes. `SECURE` env flips every guard; no other code
difference. The `secure` service exists so fixes are observable behavior,
not claimed diffs.

## Data model

```
users(id, username, password, email, role, private_note)
tickets(id, owner_id → users, title, body, is_private)
comments(id, ticket_id → tickets, author, body)
```

Seed: alice(1) owns tickets 1,4 · bob(2) owns 2 · admin(3) owns 3.
Ticket 4 is the only `is_private=0` row — the shared surface where stored
XSS lands.

## Attack flows

### V1 — SQL injection (`/api/search`, `/login`)

```
attacker ── q=' UNION SELECT … ──► Flask ── f-string ──► SQLite
   ▲                                                        │
   └──────── rows of users ─────────────────────────────────┘
Attack Flow: probe quote → error+query echo → UNION with 3 cols → creds.
Root Cause: %-interpolation of input into SQL (app.py: login/api_search).
Impact: full table read via search; auth bypass via login.
Detection: ' probe → 500 + echoed query; ' UNION … → foreign rows.
Secure Fix: ? placeholders; single generic error; no query echo.
```

### V2 — IDOR (`/api/tickets/<id>`, `/api/users/<id>`)

```
alice session ── GET /api/tickets/2 ──► lookup by id ──► 200 bob's ticket
                                    (no owner check)
Attack Flow: login → increment id → private objects returned.
Root Cause: authentication gate only; no per-object authorization.
Impact: every private ticket + private_note readable by any user.
Detection: cross-user id returns 200 instead of 403.
Secure Fix: deny unless owner or admin role, per request.
```

### V3 — Stored XSS (`POST …/comments` → `/ticket/<id>`)

```
attacker ── <script>… ──► stored in comments ──► rendered |safe ──► victim browser runs it
Attack Flow: POST probe → reload page → alert (runs as viewer).
Root Cause: raw store + |safe render (trusts data as markup).
Impact: session theft / actions as whoever reads the ticket (incl. admin).
Detection: payload bytes verbatim in HTML; alert fires.
Secure Fix: default autoescape at render + CSP header (defence in depth).
```

### V4 — SSRF (`POST /api/avatar/fetch`)

```
attacker ── {"url": internal} ──► server-side requests.get ──► /internal/secret
   ▲                                                                      │
   └──────── preview: flag{…} ────────────────────────────────────────────┘
Attack Flow: point fetcher at 127.0.0.1:5000/internal/secret → read preview.
Root Cause: unrestricted outbound fetch (any scheme/host, redirects on).
Impact: internal-only data exposed; stepping stone to metadata/sidecars.
Detection: internal content in preview field; error-oracle mapping.
Secure Fix: http(s) only, DNS-resolve + reject non-public IPs, no redirects.
```

## Trust boundaries (for class discussion)

- Browser → Flask: everything is attacker-controlled (all four vulns start here).
- Flask → SQLite: must be parameterized; the DB trusts whatever SQL it gets.
- Flask → HTTP (avatar): outbound requests carry the *server's* network
  privileges — the core SSRF insight.
- Flask → browser (ticket page): render context decides whether data stays
  data — the core XSS insight.
