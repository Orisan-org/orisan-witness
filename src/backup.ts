/**
 * Backups, off the database volume.
 *
 * The first version of this file wrote snapshots into `<dataDir>/backups`, on
 * the same Fly volume as `witness.db`, and said so in its own header comment:
 * that protects against corruption and mistakes, not against losing the
 * volume. Losing the volume is the failure that ends the service, because a
 * witness with no history cannot answer the one question it exists to answer.
 * So the snapshot now goes to object storage in a different failure domain,
 * and the on-volume copy is gone rather than kept as a comforting extra.
 *
 * Three things this does that a plain upload does not:
 *
 *  - It writes a MANIFEST alongside the database, signed by the witness key,
 *    recording the digest, the row counts and every log's head. A restore can
 *    then prove it got the right bytes back instead of assuming it.
 *  - It READS THE BACKUP BACK and compares digests before calling the run a
 *    success. A backup nobody has ever read is a hypothesis.
 *  - It records the outcome in a monitor that the status endpoint and the
 *    dead-man's-switch heartbeat both read, so a run that stops happening is
 *    itself an alertable event. See monitor.ts.
 */

import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve } from 'node:path';

import type { WitnessDb } from './db.js';
import { signPayload, verifyWithPem, type WitnessKey } from './keys.js';

export const MANIFEST_FORMAT = 1;
export const DEFAULT_RETAIN = 14;
/** Above this, read back a HEAD rather than the whole object. */
export const READBACK_LIMIT_BYTES = 256 * 1024 * 1024;

export interface ManifestLog {
  log_id: string;
  signing_pubkey: string;
  checkpoints: number;
  last_idx: number;
  last_seq_to: number;
  last_row_hash: string;
}

export interface BackupManifest {
  format: number;
  created_at: string;
  db_object: string;
  db_sha256: string;
  db_bytes: number;
  witness_pubkey_pem: string;
  checkpoint_rows: number;
  conflict_rows: number;
  logs: ManifestLog[];
  /** Ed25519 over the canonical JSON of every field above. */
  signature?: string;
}

/** The object store this witness backs up to. */
export interface BackupTarget {
  kind: 'remote' | 'local';
  describe: string;
  put(key: string, body: Buffer, contentType?: string): Promise<void>;
  get(key: string): Promise<Buffer>;
  size(key: string): Promise<number | null>;
  list(prefix: string): Promise<{ key: string; size: number }[]>;
  delete(key: string): Promise<void>;
}

export function stampFor(now: Date): string {
  return now.toISOString().replace(/[:.]/g, '-').replace(/-\d{3}Z$/, 'Z');
}

/** Read the facts a restore will be checked against, straight out of the snapshot. */
export function describeDb(db: WitnessDb, pubkeyPem: string, dbPath: string, now: Date, objectKey: string): BackupManifest {
  const raw = db.raw();
  const logs = raw.prepare('SELECT log_id, signing_pubkey FROM logs ORDER BY log_id').all() as
    { log_id: string; signing_pubkey: string }[];
  const bytes = readFileSync(dbPath);
  return {
    format: MANIFEST_FORMAT,
    created_at: now.toISOString(),
    db_object: objectKey,
    db_sha256: createHash('sha256').update(bytes).digest('hex'),
    db_bytes: bytes.length,
    witness_pubkey_pem: pubkeyPem,
    checkpoint_rows: (raw.prepare('SELECT COUNT(*) n FROM checkpoints').get() as { n: number }).n,
    conflict_rows: (raw.prepare('SELECT COUNT(*) n FROM conflicts').get() as { n: number }).n,
    logs: logs.map((l) => {
      const last = db.lastCheckpoint(l.log_id);
      return {
        log_id: l.log_id,
        signing_pubkey: l.signing_pubkey,
        checkpoints: db.allCheckpoints(l.log_id).length,
        last_idx: last?.idx ?? -1,
        last_seq_to: last?.seq_to ?? -1,
        last_row_hash: last?.row_hash ?? '',
      };
    }),
  };
}

export function signManifest(m: BackupManifest, key: WitnessKey): BackupManifest {
  const { signature: _drop, ...body } = m;
  return { ...body, signature: signPayload(key, body) };
}

export function manifestBody(m: BackupManifest): unknown {
  const { signature: _drop, ...body } = m;
  return body;
}

export interface BackupOutcome {
  stamp: string;
  dbKey: string;
  manifestKey: string;
  bytes: number;
  sha256: string;
  readBack: 'full' | 'size-only';
  pruned: string[];
  target: string;
}

export interface BackupOptions {
  db: WitnessDb;
  dbPath: string;
  key: WitnessKey;
  target: BackupTarget;
  prefix?: string;
  now?: Date;
  retain?: number;
  /** Where the online-backup snapshot is staged before upload. Never the data volume. */
  stagingDir?: string;
}

/**
 * Take one backup: snapshot, upload, read back, prune.
 *
 * Throws on any failure. The caller turns that into a loud, alertable event —
 * a backup path that swallows its own errors is the thing that lets a service
 * discover on restore day that it has nothing.
 */
export async function runBackup(opts: BackupOptions): Promise<BackupOutcome> {
  const now = opts.now ?? new Date();
  const prefix = (opts.prefix ?? 'witness').replace(/^\/+|\/+$/g, '');
  const retain = opts.retain ?? DEFAULT_RETAIN;
  const stamp = stampFor(now);
  const dbKey = `${prefix}/${stamp}/witness.db`;
  const manifestKey = `${prefix}/${stamp}/manifest.json`;

  // Staged outside the data volume, and removed in `finally` whatever happens.
  const staging = mkdtempSync(join(opts.stagingDir ?? tmpdir(), 'witness-backup-'));
  const snapshot = join(staging, 'witness.db');
  try {
    // The online backup API, not a file copy: copying a WAL-mode database out
    // from under a live writer can produce a file that will not open.
    await opts.db.raw().backup(snapshot);

    const manifest = signManifest(describeDb(opts.db, opts.key.publicKeyPem, snapshot, now, dbKey), opts.key);
    const body = readFileSync(snapshot);

    await opts.target.put(dbKey, body, 'application/vnd.sqlite3');
    await opts.target.put(manifestKey, Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8'), 'application/json');

    // Read back before claiming success.
    let readBack: 'full' | 'size-only';
    if (body.length <= READBACK_LIMIT_BYTES) {
      const fetched = await opts.target.get(dbKey);
      const got = createHash('sha256').update(fetched).digest('hex');
      if (got !== manifest.db_sha256) {
        throw new Error(`backup read-back mismatch for ${dbKey}: uploaded ${manifest.db_sha256}, read ${got}`);
      }
      readBack = 'full';
    } else {
      const size = await opts.target.size(dbKey);
      if (size !== body.length) throw new Error(`backup read-back size mismatch for ${dbKey}: ${size} != ${body.length}`);
      readBack = 'size-only';
    }

    // The pointer is written last, so it never names a backup that is not
    // fully there. A restore that follows `latest.json` always lands on a
    // complete pair.
    await opts.target.put(
      `${prefix}/latest.json`,
      Buffer.from(`${JSON.stringify({ stamp, manifest: manifestKey, db: dbKey, created_at: manifest.created_at }, null, 2)}\n`, 'utf8'),
      'application/json',
    );

    const pruned = await prune(opts.target, prefix, retain);
    return {
      stamp, dbKey, manifestKey, bytes: body.length, sha256: manifest.db_sha256,
      readBack, pruned, target: opts.target.describe,
    };
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

/** Keep the newest `retain` stamped backups; delete the rest, oldest first. */
async function prune(target: BackupTarget, prefix: string, retain: number): Promise<string[]> {
  const objects = await target.list(`${prefix}/`);
  const stamps = [...new Set(
    objects
      .map((o) => /^.*\/(\d{4}-\d{2}-\d{2}T[\d-]+Z)\/[^/]+$/.exec(o.key)?.[1])
      .filter((s): s is string => Boolean(s)),
  )].sort();
  const doomed = stamps.slice(0, Math.max(0, stamps.length - retain));
  const removed: string[] = [];
  for (const s of doomed) {
    for (const o of objects.filter((x) => x.key.includes(`/${s}/`))) {
      await target.delete(o.key);
      removed.push(o.key);
    }
  }
  return removed;
}

// --- targets ---------------------------------------------------------------

/**
 * A directory target. Used by tests and by anyone deliberately backing up to a
 * mounted volume elsewhere. `isOnDataVolume` is what lets the status endpoint
 * call out the configuration this whole change exists to remove.
 */
export function localTarget(dir: string): BackupTarget & { root: string } {
  const root = resolve(dir);
  const pathFor = (key: string): string => join(root, key);
  return {
    kind: 'local',
    root,
    describe: `local:${root}`,
    async put(key, body) { mkdirSync(join(pathFor(key), '..'), { recursive: true }); writeFileSync(pathFor(key), body); },
    async get(key) { return readFileSync(pathFor(key)); },
    async size(key) { try { return statSync(pathFor(key)).size; } catch { return null; } },
    async list(prefix) {
      const out: { key: string; size: number }[] = [];
      const walk = (d: string): void => {
        let entries;
        try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
        for (const e of entries) {
          const p = join(d, e.name);
          if (e.isDirectory()) walk(p);
          else {
            const key = relative(root, p).split(/[\\/]/).join('/');
            if (key.startsWith(prefix)) out.push({ key, size: statSync(p).size });
          }
        }
      };
      walk(root);
      return out;
    },
    async delete(key) { rmSync(pathFor(key), { force: true }); },
  };
}

export function isOnDataVolume(targetRoot: string, dataDir: string): boolean {
  const rel = relative(resolve(dataDir), resolve(targetRoot));
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

export function s3Target(client: {
  bucket: string; endpoint: string;
  put(k: string, b: Buffer, ct?: string): Promise<void>;
  get(k: string): Promise<Buffer>;
  list(p: string): Promise<{ key: string; size: number }[]>;
  delete(k: string): Promise<void>;
  exists(k: string): Promise<boolean>;
}): BackupTarget {
  return {
    kind: 'remote',
    describe: `s3:${client.bucket} @ ${client.endpoint}`,
    put: (k, b, ct) => client.put(k, b, ct),
    get: (k) => client.get(k),
    async size(k) {
      const objs = await client.list(k);
      return objs.find((o) => o.key === k)?.size ?? null;
    },
    list: (p) => client.list(p),
    delete: (k) => client.delete(k),
  };
}

export function verifyManifestSignature(m: BackupManifest, pubkeyPem?: string): boolean {
  if (!m.signature) return false;
  return verifyWithPem(pubkeyPem ?? m.witness_pubkey_pem, manifestBody(m), m.signature);
}
