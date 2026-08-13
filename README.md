# orisan-witness

External memory for Orisan runtime records. It remembers checkpoints that the
operator can later delete, and that is the entire job.

## Why it exists

A log the operator holds alone cannot prove it is complete. Delete the trailing
events, the checkpoint covering them, and its anchors, and what remains is a
valid shorter log — contiguous from the start, internally consistent, signed and
timestamped. Nothing inside it can tell.

The recorder's own security review confirmed this by execution. The fix is not
more cryptography; it is a second party who remembers. Without a witness the
recorder can be honest but can only ever reach exit 2. With one, exit 0 becomes
truthful.

## What it stores, and what it cannot

    log_id, index, seq range, merkle_root,
    client signature, witnessed_at, witness signature, prev_row_hash

That is the whole schema. No event content, no tool arguments, no payloads, no
file paths, no prompts. A test pins the column list and greps the schema for
content-shaped words, because "we don't look at your data" is worth nothing as a
promise and quite a lot as a constraint the build enforces.

The witness learns **how much** happened. It never learns **what**.

## Trust properties

| Property | How |
|---|---|
| Deleting local checkpoints does not hide them | the head reports the highest index ever witnessed |
| A substituted witness cannot answer for us | the recorder pins our key at registration and never re-learns it |
| We cannot silently rewrite our own history | each row carries the hash of its predecessor for that log |
| We cannot quietly edit a row | `UPDATE`/`DELETE` raise from a database trigger, not a code convention |
| A fork attempt is visible, not just refused | 409 plus an append-only conflicts row, surfaced on the head |
| An auditor does not need the operator's permission | `GET /head` is public and unauthenticated |

## API

    POST /v1/logs                          register a log, pin its signing key
    POST /v1/logs/:log_id/checkpoints      submit a checkpoint, get a signed receipt
    GET  /v1/logs/:log_id/head             the latest witnessed checkpoint  (public)
    GET  /v1/pubkey                        our Ed25519 public key, SPKI PEM
    GET  /health

Registering an existing `log_id` with a different key is `409`. Key rotation is
out of scope for W1 — accepting a new key silently would orphan every checkpoint
already held and defeat the pinning the client depends on.

## Running it

    npm install && npm run build
    WITNESS_DB=./data/witness.db WITNESS_KEY=./data/witness-signing.key node dist/index.js

The public key is printed to the log at boot so an operator can pin it from
there rather than from a page that could later be swapped.

## Deploying to Fly.io

**One machine, deliberately.** The store is SQLite on a volume. Two machines
would be two divergent witnesses, and a customer checking a head could get
either answer — worse than having none. `fly.toml` therefore pins
`min_machines_running = 1` with autoscaling and auto-stop off. Horizontal scale
needs Postgres or a consensus layer; that is a v2 decision, not a config flag.

    fly auth login
    fly launch --no-deploy --copy-config --name orisan-witness
    fly volumes create witness_data --size 1 --region lhr
    fly deploy
    fly logs                       # the boot line contains the public key
    curl https://orisan-witness.fly.dev/v1/pubkey

Then publish that PEM at a stable URL so auditors can pin it independently.

### Custom domain

The certificate for `witness.orisan.org` is created. It stays **Not verified**
until DNS resolves, and the hostname will not serve traffic before then.

`orisan.org` is on Namecheap (`dns1/dns2.registrar-servers.com`). Add ONE of
these in Namecheap → Domain List → Manage → Advanced DNS:

**CNAME (use this one).** A subdomain should be a CNAME: it follows Fly if the
underlying addresses ever change, and the IPv4 below is a *shared* Fly address
rather than one allocated to this app.

    Type   Host      Value                                   TTL
    CNAME  witness   320welg.orisan-witness.fly.dev.         Automatic

**A + AAAA (Fly's default suggestion).** Works, but pins two addresses that Fly
may rotate:

    A      witness   66.241.125.17
    AAAA   witness   2a09:8280:1::16a:3a9f:0

Note `www` already uses a CNAME to Vercel, so the zone is CNAME-friendly.

Then:

    fly certs check witness.orisan.org      # issues once DNS resolves
    curl https://witness.orisan.org/health

Nothing pinned in a recorder changes by adding DNS. A registered log keeps
talking to whatever URL it pinned; moving it is a deliberate act, via
`orisan-rec witness repoint`.

### Backups

A daily in-process backup runs via SQLite's online backup API (copying a
WAL-mode file out from under a live writer can produce something that will not
open). Fourteen are retained; an unbounded backup directory fills the volume and
takes the service down with it.

**These backups are on the same volume as the database.** That protects against
corruption and mistakes, not against losing the volume. Off-box copies are a v2
item, and until they exist nobody should call this disaster recovery.

    fly ssh console -C "ls -la /data/backups"

## Out of scope for W1

Multi-tenant auth, billing, key rotation, federation, multiple witnesses,
transparency-log gossip, off-box backups, horizontal scale. All v2.
