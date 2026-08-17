/**
 * The restore drill.
 *
 * This is the test the backup work exists for. It runs a real witness process,
 * puts real signed checkpoints into it, backs up to a real S3-compatible
 * server over a real socket, then DELETES THE ENTIRE DATA VOLUME — database,
 * WAL, signing key, everything — and brings a second process up from the
 * backup alone. The bar is that the new instance answers `/v1/logs/:id/head`
 * byte for byte as the destroyed one did, under the same witness identity.
 *
 * Anything less is not a restore. A witness that comes back with a new key is
 * a stranger: every client pinned the old key at registration and will reject
 * it with key_mismatch, so the history it holds is unusable even though the
 * rows are all there.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createHash, generateKeyPairSync, sign as edSign, createPublicKey } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';

import { canonicalJson } from '../src/canon.js';
import { s3Target, type BackupManifest } from '../src/backup.js';
import { restore } from '../src/restore.js';
import { S3Client } from '../src/s3.js';
import { startFakeS3, type FakeS3 } from './fixtures/fake-s3.js';
import { spawnWitness, type LiveWitness } from './fixtures/live-witness.js';

const PREFIX = 'witness';

/** A client log: its own Ed25519 key, signing exactly what the service checks. */
function makeClient(): { logId: string; pubkeyPem: string; sign: (p: unknown) => string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    logId: crypto.randomUUID(),
    pubkeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    sign: (p) => edSign(null, Buffer.from(canonicalJson(p), 'utf8'), privateKey).toString('base64'),
  };
}

const post = async (url: string, body: unknown): Promise<{ status: number; json: any }> => {
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, json: await r.json() };
};
const get = async (url: string): Promise<{ status: number; json: any }> => {
  const r = await fetch(url);
  return { status: r.status, json: await r.json() };
};

// A key generated here, handed to both processes the way a Fly secret would be.
const { privateKey: witnessPriv } = generateKeyPairSync('ed25519');
const WITNESS_KEY_PEM = witnessPriv.export({ type: 'pkcs8', format: 'pem' }).toString();
const WITNESS_PUBKEY = createPublicKey(witnessPriv).export({ type: 'spki', format: 'pem' }).toString();

let s3: FakeS3;
let volumeA: string;
let volumeB: string;
let first: LiveWitness;
let headsBefore: Record<string, unknown> = {};
let clients: ReturnType<typeof makeClient>[] = [];
/**
 * The stamp of the backup taken AFTER the last write.
 *
 * Pinned deliberately. The scheduler takes one backup at boot, before anything
 * is registered, so the bucket legitimately holds an empty manifest too — and
 * the restored instance takes its own on startup. A test that just grabs "a
 * manifest" grabs whichever, and this one did until it failed.
 */
let stamp = '';

const envFor = (dataDir: string): Record<string, string> => ({
  WITNESS_DB: join(dataDir, 'witness.db'),
  WITNESS_KEY: join(dataDir, 'witness-signing.key'),
  WITNESS_KEY_PEM,
  WITNESS_BACKUP_ENDPOINT: s3.url,
  WITNESS_BACKUP_BUCKET: s3.bucket,
  WITNESS_BACKUP_REGION: 'auto',
  AWS_ACCESS_KEY_ID: s3.config.accessKeyId,
  AWS_SECRET_ACCESS_KEY: s3.config.secretAccessKey,
  WITNESS_BACKUP_PREFIX: PREFIX,
  WITNESS_BACKUP_INTERVAL_MS: '1000',
});

beforeAll(async () => {
  s3 = await startFakeS3();
  volumeA = mkdtempSync(join(tmpdir(), 'witness-volume-a-'));
  volumeB = mkdtempSync(join(tmpdir(), 'witness-volume-b-'));

  first = await spawnWitness(envFor(volumeA));

  // Three logs, several checkpoints each, plus a recorded fork on one of them
  // so the restore has to carry conflict rows too.
  clients = [makeClient(), makeClient(), makeClient()];
  for (const c of clients) {
    const reg = await post(`${first.url}/v1/logs`, { log_id: c.logId, signing_pubkey: c.pubkeyPem });
    expect(reg.status, JSON.stringify(reg.json)).toBe(200);
    let seq = 0;
    for (let i = 0; i < 4; i++) {
      const body = {
        index: i, seq_from: seq, seq_to: seq + 9,
        merkle_root: createHash('sha256').update(`${c.logId}:${i}`).digest('hex'),
      };
      const r = await post(`${first.url}/v1/logs/${c.logId}/checkpoints`, {
        ...body, signature: c.sign({ log_id: c.logId, ...body }),
      });
      expect(r.status, JSON.stringify(r.json)).toBe(200);
      seq += 10;
    }
  }
  // A fork attempt on the first log: same index, different root.
  const forked = { index: 3, seq_from: 30, seq_to: 39, merkle_root: createHash('sha256').update('fork').digest('hex') };
  const forkRes = await post(`${first.url}/v1/logs/${clients[0]!.logId}/checkpoints`, {
    ...forked, signature: clients[0]!.sign({ log_id: clients[0]!.logId, ...forked }),
  });
  expect(forkRes.status).toBe(409);

  for (const c of clients) headsBefore[c.logId] = (await get(`${first.url}/v1/logs/${c.logId}/head`)).json;

  // Wait for a backup taken AFTER the last write.
  const deadline = Date.now() + 30_000;
  for (;;) {
    const st = await get(`${first.url}/v1/backup-status`);
    if (st.json.state === 'ok' && st.json.last_backup
        && new Date(st.json.last_success_at).getTime() > 0
        && s3.objects.has(`${PREFIX}/${st.json.last_backup.stamp}/manifest.json`)) {
      const m = JSON.parse(s3.objects.get(`${PREFIX}/${st.json.last_backup.stamp}/manifest.json`)!.toString()) as BackupManifest;
      if (m.checkpoint_rows === 12) { stamp = st.json.last_backup.stamp as string; break; }
    }
    if (Date.now() > deadline) throw new Error(`no complete backup appeared: ${JSON.stringify(st.json)}`);
    await new Promise((r) => setTimeout(r, 300));
  }
}, 120_000);

afterAll(async () => {
  await first?.stop();
  await s3?.stop();
  for (const d of [volumeA, volumeB]) if (d) rmSync(d, { recursive: true, force: true });
});

const targetFor = (): ReturnType<typeof s3Target> => s3Target(new S3Client(s3.config));

describe('the backup that was taken', () => {
  it('holds a database, a manifest and a pointer — and nothing on the data volume', () => {
    const keys = [...s3.objects.keys()].sort();
    expect(keys).toContain(`${PREFIX}/${stamp}/witness.db`);
    expect(keys).toContain(`${PREFIX}/${stamp}/manifest.json`);
    expect(keys).toContain(`${PREFIX}/latest.json`);
    // The old code wrote <dataDir>/backups. Nothing should now.
    expect(readdirSync(volumeA)).not.toContain('backups');
  });

  it('was read back off the far end before being called a success', () => {
    const dbKey = `${PREFIX}/${stamp}/witness.db`;
    expect(s3.calls.filter((c) => c.method === 'GET' && c.key === dbKey).length).toBeGreaterThan(0);
  });

  it('records every log head and is signed by the witness key', () => {
    const m = JSON.parse(s3.objects.get(`${PREFIX}/${stamp}/manifest.json`)!.toString()) as BackupManifest;
    expect(m.witness_pubkey_pem.trim()).toBe(WITNESS_PUBKEY.trim());
    expect(m.logs).toHaveLength(3);
    expect(m.checkpoint_rows).toBe(12);
    expect(m.conflict_rows).toBe(1);
    expect(m.signature).toBeTruthy();
  });
});

describe('losing the volume entirely', () => {
  let second: LiveWitness;

  it('restores into a clean directory with every check passing', async () => {
    await first.stop();
    // The whole volume: database, WAL, and the signing key that used to be the
    // only copy of this witness's identity.
    rmSync(volumeA, { recursive: true, force: true });
    expect(existsSync(join(volumeA, 'witness.db'))).toBe(false);

    const report = await restore({
      target: targetFor(), destDir: volumeB, prefix: PREFIX, stamp,
      expectPubkeyPem: WITNESS_PUBKEY,
    });
    expect(report.failures, report.failures.join('; ')).toEqual([]);
    expect(report.ok).toBe(true);
    expect(report.checks).toHaveLength(10);
    expect(report.checks.every((c) => c.ok)).toBe(true);
  }, 60_000);

  it('comes back up as a working service', async () => {
    second = await spawnWitness({ ...envFor(volumeB), WITNESS_BACKUP_INTERVAL_MS: '86400000' });
    const health = await get(`${second.url}/health`);
    expect(health.status).toBe(200);
  }, 60_000);

  it('has the same identity, so pinned clients still accept it', async () => {
    const pk = await get(`${second.url}/v1/pubkey`);
    expect(pk.json.public_key_pem.trim()).toBe(WITNESS_PUBKEY.trim());
    expect(second.pubkeyPem.trim()).toBe(first.pubkeyPem.trim());
  });

  it('answers every head byte for byte as the destroyed instance did', async () => {
    for (const c of clients) {
      const after = (await get(`${second.url}/v1/logs/${c.logId}/head`)).json;
      expect(after, `head for ${c.logId}`).toEqual(headsBefore[c.logId]);
    }
  });

  it('still remembers the fork it recorded', async () => {
    const head = (await get(`${second.url}/v1/logs/${clients[0]!.logId}/head`)).json;
    expect(head.conflict).toBe(true);
    expect(head.conflict_count).toBe(1);
  });

  it('still refuses to accept a rewrite of history', async () => {
    const c = clients[1]!;
    const body = { index: 1, seq_from: 10, seq_to: 19, merkle_root: createHash('sha256').update('rewrite').digest('hex') };
    const r = await post(`${second.url}/v1/logs/${c.logId}/checkpoints`, { ...body, signature: c.sign({ log_id: c.logId, ...body }) });
    expect(r.status).toBe(409);
  });

  it('accepts the next real checkpoint, continuing the chain it restored', async () => {
    const c = clients[2]!;
    const body = { index: 4, seq_from: 40, seq_to: 49, merkle_root: createHash('sha256').update('next').digest('hex') };
    const r = await post(`${second.url}/v1/logs/${c.logId}/checkpoints`, { ...body, signature: c.sign({ log_id: c.logId, ...body }) });
    expect(r.status, JSON.stringify(r.json)).toBe(200);
    expect(r.json.index).toBe(4);
  });

  it('restored a database that is still append-only', () => {
    const db = new Database(join(volumeB, 'witness.db'));
    try {
      expect(() => db.prepare('DELETE FROM checkpoints').run()).toThrow(/append-only/);
      expect(() => db.prepare("UPDATE checkpoints SET merkle_root = 'x'").run()).toThrow(/append-only/);
    } finally { db.close(); }
  });

  afterAll(async () => { await second?.stop(); });
});

describe('restore refuses what it should refuse', () => {
  const freshDir = (): string => mkdtempSync(join(tmpdir(), 'witness-restore-'));

  it('will not restore over a directory that already holds something', async () => {
    const d = freshDir();
    writeFileSync(join(d, 'witness.db'), 'a live database, probably');
    await expect(restore({ target: targetFor(), destDir: d, prefix: PREFIX, stamp })).rejects.toThrow(/refusing to restore over it/);
    rmSync(d, { recursive: true, force: true });
  });

  it('fails the pinned check when the manifest names a different witness key', async () => {
    const other = createPublicKey(generateKeyPairSync('ed25519').privateKey).export({ type: 'spki', format: 'pem' }).toString();
    const d = freshDir();
    const r = await restore({ target: targetFor(), destDir: d, prefix: PREFIX, stamp, expectPubkeyPem: other });
    expect(r.ok).toBe(false);
    expect(r.failures.join(' ')).toMatch(/DIFFERENT witness key/);
    rmSync(d, { recursive: true, force: true });
  });

  it('catches a corrupted database object', async () => {
    const dbKey = `${PREFIX}/${stamp}/witness.db`;
    const good = s3.objects.get(dbKey)!;
    s3.objects.set(dbKey, Buffer.concat([good.subarray(0, 200), Buffer.from('rot'), good.subarray(203)]));
    const d = freshDir();
    try {
      const r = await restore({ target: targetFor(), destDir: d, prefix: PREFIX, stamp, expectPubkeyPem: WITNESS_PUBKEY });
      expect(r.ok).toBe(false);
      expect(r.failures.join(' ')).toMatch(/database digest/);
    } finally {
      s3.objects.set(dbKey, good);
      rmSync(d, { recursive: true, force: true });
    }
  });

  it('catches a manifest edited by whoever controls the bucket', async () => {
    const key = `${PREFIX}/${stamp}/manifest.json`;
    const good = s3.objects.get(key)!;
    const m = JSON.parse(good.toString()) as BackupManifest;
    // Someone with write access to the bucket shaves a log off the record.
    // They cannot re-sign, because the signing key is not in the bucket.
    m.logs = m.logs.slice(0, 2);
    m.checkpoint_rows = 8;
    s3.objects.set(key, Buffer.from(JSON.stringify(m)));
    const d = freshDir();
    try {
      const r = await restore({ target: targetFor(), destDir: d, prefix: PREFIX, stamp, expectPubkeyPem: WITNESS_PUBKEY });
      expect(r.ok).toBe(false);
      expect(r.failures.join(' ')).toMatch(/manifest signature/);
      // And the count check catches it independently of the signature.
      expect(r.failures.join(' ')).toMatch(/row counts|logs present/);
    } finally {
      s3.objects.set(key, good);
      rmSync(d, { recursive: true, force: true });
    }
  });
});
