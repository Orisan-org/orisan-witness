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

`witness.orisan.org` is **live**: DNS resolves to the Fly app, the certificate
is issued, and `GET /health` and `GET /v1/pubkey` answer over HTTPS. The
recorder's `showcase` uses it by default.

The record in place is the CNAME below. The rest of this section is kept as the
procedure for standing up another hostname.

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

### Backups and restore

Backups go to **Tigris object storage**, a different failure domain from the
Fly volume the database lives on. `fly storage create` injects the AWS_*
credentials and BUCKET_NAME as secrets; the service needs no further
configuration.

Each run writes three objects:

    witness/<stamp>/witness.db      SQLite online-backup snapshot
    witness/<stamp>/manifest.json   digest, row counts, every log's head — signed
    witness/latest.json             pointer, written LAST

The pointer is written last on purpose, so it never names a half-uploaded
backup. Fourteen stamps are retained. The snapshot is staged in the system temp
directory, never on the data volume, and removed whatever happens.

Two things a plain `aws s3 cp` would not do:

- The manifest is **signed by the witness key**. Whoever controls the bucket can
  delete objects, but cannot forge a manifest that claims a different history.
- The run **reads the object back** and compares digests before recording
  success. A backup nobody has ever read is a hypothesis.

If no destination is configured the service backs up **nothing** and says so.
It deliberately does not fall back to the data volume, because that would look
healthy while rebuilding the single point of failure this replaced.

#### Restore

    AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_ENDPOINT_URL_S3=... \
    BUCKET_NAME=orisan-witness-backups \
    node dist/index.js restore --to ./restored --from latest \
      --expect-pubkey witness-pubkey.pem

Ten checks run, and the command exits non-zero if any fails: manifest format,
manifest signature under the **pinned** key, database digest, SQLite
`integrity_check`, the append-only triggers still being present, checkpoint and
conflict row counts, the set of logs, every log's self-chain, every head against
the manifest, and every checkpoint's witness signature.

`--expect-pubkey` is what makes the signature check mean anything. Without it
the manifest only vouches for itself.

`test/restore.test.ts` runs this whole drill on every test run: it starts a real
witness, writes real checkpoints, **deletes the entire data volume**, restores
from the backup and asserts the new process answers every head byte for byte as
the destroyed one did.

#### The signing key must outlive the volume

The witness identity is an Ed25519 key at `/data/witness-signing.key` — on the
volume. Losing the volume loses the key as well as the database, and restoring
the history under a fresh key produces a witness that every client rejects with
`key_mismatch`, because clients pin the key at registration. The rows would all
be there and be worthless.

So the key belongs in a Fly secret, which lives off the machine. Pipe it to
`fly secrets import`, which reads stdin — do not use `fly secrets set`, which
takes the value as an argument and so exposes the private key in `ps` output
and in shell history:

    KEY=$(fly ssh console -a orisan-witness \
            -C "base64 -w0 /data/witness-signing.key" | tr -d '\r\n')
    [ ${#KEY} -gt 160 ] || { echo "extraction looks truncated; aborting"; return 1; }
    printf 'WITNESS_KEY_PEM=%s\n' "$KEY" | fly secrets import -a orisan-witness
    unset KEY

The length guard matters: a truncated extraction would otherwise be stored as
the identity, and the failure would only surface when clients start rejecting
the witness.

`WITNESS_KEY_PEM` takes precedence over the file and is never written to disk.
If both are present and **differ**, the service refuses to start rather than
silently picking an identity based on deployment order.

### Knowing when backups stop

The failure this guards against is silence — a backup loop that throws into a
log nobody reads, or a machine that is simply gone. Two signals, deliberately of
opposite kinds:

**`GET /v1/backup-status`** — 200 when healthy, **503** when the last success is
older than `WITNESS_BACKUP_MAX_AGE_SECONDS` (default 26h), when the last run
failed, when the destination is on the data volume, or when nothing is
configured. The body names the reason. Failures are also logged with
`"alert": true` for a log-drain filter.

**A dead-man's-switch heartbeat** — set `WITNESS_BACKUP_HEARTBEAT_URL` (a
healthchecks.io-style check) and every successful backup pings it, every failure
pings `<url>/fail`. The alert is the **absence** of a ping, raised by something
that is not us. This is the one that survives the machine being destroyed, which
is exactly when an on-box alert never arrives.

    fly secrets set WITNESS_BACKUP_HEARTBEAT_URL=https://hc-ping.com/<uuid> -a orisan-witness

**`/health` is liveness only and must stay that way.** Fly restarts, then stops
routing to, a machine that fails its health check. Folding backup freshness into
`/health` would mean a broken bucket takes the witness offline — and an
unreachable witness makes every customer's `verify` return exit 2, "cannot
verify". Degrading the product's core promise because a backup is late is
strictly worse than a late backup.

## Out of scope for W1

Multi-tenant auth, billing, key rotation, federation, multiple witnesses,
transparency-log gossip, horizontal scale. All v2.
