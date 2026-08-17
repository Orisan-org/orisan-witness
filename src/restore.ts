/**
 * Restore, and the checks that make a restore worth having.
 *
 * "We take backups" is a claim about a cron job. "This backup restores into a
 * working witness with the same identity and the same history" is a claim
 * about the thing you actually need on the worst day, and it is only true if
 * someone has done it. This module does it, end to end, and test/restore.test.ts
 * runs it against a live server every time the suite runs.
 *
 * Ten checks, in the order a sceptic would ask them:
 *
 *   1. the manifest exists and is a format we know
 *   2. the manifest's signature verifies — against a PINNED key if one was
 *      supplied, because a manifest that only vouches for itself vouches for
 *      nothing against whoever controls the bucket
 *   3. the database object's digest matches the manifest
 *   4. SQLite's own integrity_check passes
 *   5. the append-only triggers survived — a restore into a database where
 *      UPDATE and DELETE work again is a restore into something that is no
 *      longer a witness
 *   6. checkpoint and conflict row counts match the manifest
 *   7. the same set of logs is present
 *   8. every log's self-chain of row hashes verifies
 *   9. every log's head matches the manifest's record of it
 *  10. every checkpoint's witness signature still verifies under the witness
 *      key — the restored rows are still attributable, not just present
 *
 * The identity problem this exposed is worth stating plainly: the signing key
 * lives on the same volume as the database, so a volume loss used to destroy
 * BOTH. Restoring the data under a fresh key produces a witness that every
 * client rejects with key_mismatch, which is not a restore. Hence
 * WITNESS_KEY_PEM in keys.ts, and check 2's pinned form here.
 */

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { verifyManifestSignature, type BackupManifest, type BackupTarget, MANIFEST_FORMAT } from './backup.js';
import { WitnessDb } from './db.js';
import { verifyWithPem } from './keys.js';
import { receiptSignedPayload } from './service.js';

export interface RestoreCheck { name: string; ok: boolean; detail: string }

export interface RestoreReport {
  ok: boolean;
  stamp: string;
  dbPath: string;
  manifest: BackupManifest;
  checks: RestoreCheck[];
  failures: string[];
}

export interface RestoreOptions {
  target: BackupTarget;
  destDir: string;
  prefix?: string;
  /** A stamp, or 'latest' to follow the pointer object. */
  stamp?: string;
  /** Pinned witness public key. Supplying it is what makes check 2 mean something. */
  expectPubkeyPem?: string;
  /** Refuse to write into a directory that already holds a database. */
  force?: boolean;
}

export async function resolveStamp(target: BackupTarget, prefix: string, stamp?: string): Promise<string> {
  if (stamp && stamp !== 'latest') return stamp;
  const pointer = JSON.parse((await target.get(`${prefix}/latest.json`)).toString('utf8')) as { stamp?: string };
  if (!pointer.stamp) throw new Error(`${prefix}/latest.json does not name a stamp`);
  return pointer.stamp;
}

export async function restore(opts: RestoreOptions): Promise<RestoreReport> {
  const prefix = (opts.prefix ?? 'witness').replace(/^\/+|\/+$/g, '');
  const stamp = await resolveStamp(opts.target, prefix, opts.stamp);
  const dest = resolve(opts.destDir);

  // A clean instance means clean. Silently restoring on top of a live database
  // is how you turn a recovery into a second incident.
  mkdirSync(dest, { recursive: true });
  const existing = readdirSync(dest).filter((f) => !f.startsWith('.'));
  if (existing.length > 0 && !opts.force) {
    throw new Error(`${dest} is not empty (${existing.slice(0, 5).join(', ')}); refusing to restore over it without force`);
  }

  const checks: RestoreCheck[] = [];
  const add = (name: string, ok: boolean, detail: string): void => { checks.push({ name, ok, detail }); };

  const manifest = JSON.parse(
    (await opts.target.get(`${prefix}/${stamp}/manifest.json`)).toString('utf8'),
  ) as BackupManifest;

  add('manifest format', manifest.format === MANIFEST_FORMAT,
    `format ${manifest.format} (expected ${MANIFEST_FORMAT})`);

  const pinned = opts.expectPubkeyPem?.trim();
  if (pinned) {
    const sameKey = pinned === manifest.witness_pubkey_pem.trim();
    add('manifest signature (pinned key)',
      sameKey && verifyManifestSignature(manifest, pinned),
      sameKey
        ? 'signed by the pinned witness key'
        : 'manifest names a DIFFERENT witness key than the one pinned — restoring this produces an identity clients will reject');
  } else {
    add('manifest signature (unpinned)', verifyManifestSignature(manifest),
      'self-consistent only: no --expect-pubkey was given, so this proves the manifest is undamaged, not that it is ours');
  }

  const body = await opts.target.get(manifest.db_object);
  const sha = createHash('sha256').update(body).digest('hex');
  add('database digest', sha === manifest.db_sha256 && body.length === manifest.db_bytes,
    `${body.length} bytes, sha256 ${sha.slice(0, 16)}…`);

  const dbPath = join(dest, 'witness.db');
  writeFileSync(dbPath, body);

  const db = new WitnessDb(dbPath);
  try {
    const integrity = (db.raw().prepare('PRAGMA integrity_check').get() as { integrity_check: string }).integrity_check;
    add('sqlite integrity_check', integrity === 'ok', integrity);

    const triggers = (db.raw()
      .prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name")
      .all() as { name: string }[]).map((r) => r.name);
    const required = ['checkpoints_no_delete', 'checkpoints_no_update', 'conflicts_no_delete', 'conflicts_no_update', 'logs_no_key_change'];
    const missing = required.filter((t) => !triggers.includes(t));
    add('append-only triggers', missing.length === 0,
      missing.length ? `MISSING: ${missing.join(', ')}` : `all ${required.length} present`);

    const cpRows = (db.raw().prepare('SELECT COUNT(*) n FROM checkpoints').get() as { n: number }).n;
    const cfRows = (db.raw().prepare('SELECT COUNT(*) n FROM conflicts').get() as { n: number }).n;
    add('row counts', cpRows === manifest.checkpoint_rows && cfRows === manifest.conflict_rows,
      `${cpRows} checkpoints (manifest ${manifest.checkpoint_rows}), ${cfRows} conflicts (manifest ${manifest.conflict_rows})`);

    const logIds = (db.raw().prepare('SELECT log_id FROM logs ORDER BY log_id').all() as { log_id: string }[])
      .map((r) => r.log_id);
    add('logs present', logIds.length === manifest.logs.length,
      `${logIds.length} logs (manifest ${manifest.logs.length})`);

    const chainBreaks = logIds.flatMap((id) => db.verifyRowChain(id).map((b) => `${id}#${b.idx}: ${b.reason}`));
    add('witness row chains', chainBreaks.length === 0,
      chainBreaks.length ? chainBreaks.slice(0, 3).join('; ') : `${logIds.length} chain(s) intact`);

    const headMismatch: string[] = [];
    for (const m of manifest.logs) {
      const last = db.lastCheckpoint(m.log_id);
      const idx = last?.idx ?? -1;
      const seqTo = last?.seq_to ?? -1;
      const rowHashV = last?.row_hash ?? '';
      if (idx !== m.last_idx || seqTo !== m.last_seq_to || rowHashV !== m.last_row_hash) {
        headMismatch.push(`${m.log_id}: restored idx ${idx}/seq ${seqTo}, manifest ${m.last_idx}/${m.last_seq_to}`);
      }
    }
    add('heads match the manifest', headMismatch.length === 0,
      headMismatch.length ? headMismatch.slice(0, 3).join('; ') : `${manifest.logs.length} head(s) as recorded`);

    const pubkey = pinned ?? manifest.witness_pubkey_pem;
    let checked = 0;
    const badSigs: string[] = [];
    for (const id of logIds) {
      for (const row of db.allCheckpoints(id)) {
        checked++;
        const payload = receiptSignedPayload({
          log_id: row.log_id, index: row.idx, seq_from: row.seq_from,
          seq_to: row.seq_to, merkle_root: row.merkle_root, witnessed_at: row.witnessed_at,
        });
        if (!verifyWithPem(pubkey, payload, row.witness_signature)) badSigs.push(`${id}#${row.idx}`);
      }
    }
    add('witness signatures on every checkpoint', badSigs.length === 0,
      badSigs.length ? `${badSigs.length} bad: ${badSigs.slice(0, 5).join(', ')}` : `${checked} signature(s) verify under ${pinned ? 'the pinned' : "the manifest's"} key`);
  } finally {
    db.close();
  }

  const failures = checks.filter((c) => !c.ok).map((c) => `${c.name}: ${c.detail}`);
  return { ok: failures.length === 0, stamp, dbPath, manifest, checks, failures };
}

export function formatReport(r: RestoreReport): string {
  const lines = [
    `restore ${r.stamp} -> ${r.dbPath}`,
    `  taken ${r.manifest.created_at}, ${r.manifest.db_bytes} bytes, ${r.manifest.logs.length} log(s), ${r.manifest.checkpoint_rows} checkpoint(s)`,
    '',
  ];
  for (const c of r.checks) lines.push(`  ${c.ok ? 'ok  ' : 'FAIL'}  ${c.name.padEnd(38)} ${c.detail}`);
  lines.push('');
  lines.push(r.ok
    ? '  RESTORE VERIFIED — this database is a working witness with the recorded history.'
    : `  RESTORE FAILED — ${r.failures.length} check(s) did not pass. Do not put this into service.`);
  if (!existsSync(r.dbPath)) lines.push('  (no database was written)');
  return `${lines.join('\n')}\n`;
}
