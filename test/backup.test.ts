/**
 * Backups, the monitor, and the endpoints that make a stopped backup loud.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, createPublicKey } from 'node:crypto';

import {
  isOnDataVolume, localTarget, runBackup, s3Target, stampFor,
  verifyManifestSignature, type BackupManifest, type BackupOutcome,
} from '../src/backup.js';
import { WitnessDb } from '../src/db.js';
import { loadKeyFromPem, loadOrCreateKey, type WitnessKey } from '../src/keys.js';
import { BackupMonitor, scheduleBackups } from '../src/monitor.js';
import { S3Client } from '../src/s3.js';
import { WitnessService } from '../src/service.js';
import { createApp } from '../src/server.js';
import { startFakeS3, type FakeS3 } from './fixtures/fake-s3.js';

let dataDir: string;
let db: WitnessDb;
let key: WitnessKey;
let s3: FakeS3;

const manifestFrom = (f: FakeS3, stamp: string): BackupManifest =>
  JSON.parse(f.objects.get(`witness/${stamp}/manifest.json`)!.toString()) as BackupManifest;

beforeEach(async () => {
  dataDir = mkdtempSync(join(tmpdir(), 'witness-backup-'));
  db = new WitnessDb(join(dataDir, 'witness.db'));
  key = loadOrCreateKey(join(dataDir, 'k.pem'), {} as NodeJS.ProcessEnv);
  s3 = await startFakeS3();
});
afterEach(async () => {
  db.close();
  await s3.stop();
  rmSync(dataDir, { recursive: true, force: true });
});

const target = (): ReturnType<typeof s3Target> => s3Target(new S3Client(s3.config));
const backup = (now = new Date('2026-08-17T03:00:00Z'), retain?: number): Promise<BackupOutcome> =>
  runBackup({ db, dbPath: join(dataDir, 'witness.db'), key, target: target(), now, ...(retain !== undefined ? { retain } : {}) });

describe('a backup lands off the data volume', () => {
  it('uploads the database, a manifest and a pointer', async () => {
    const out = await backup();
    expect([...s3.objects.keys()].sort()).toEqual([
      'witness/2026-08-17T03-00-00Z/manifest.json',
      'witness/2026-08-17T03-00-00Z/witness.db',
      'witness/latest.json',
    ]);
    expect(out.readBack).toBe('full');
    expect(JSON.parse(s3.objects.get('witness/latest.json')!.toString()).stamp).toBe(out.stamp);
  });

  it('writes nothing to the data volume, not even a staging file', async () => {
    await backup();
    expect(readdirSync(dataDir).filter((f) => f !== 'witness.db' && f !== 'k.pem' && !f.startsWith('witness.db-')))
      .toEqual([]);
    expect(existsSync(join(dataDir, 'backups'))).toBe(false);
  });

  it('signs the manifest with the witness key', async () => {
    const out = await backup();
    const m = manifestFrom(s3, out.stamp);
    expect(verifyManifestSignature(m, key.publicKeyPem)).toBe(true);
  });

  it('a manifest edited after the fact no longer verifies', async () => {
    const out = await backup();
    const m = manifestFrom(s3, out.stamp);
    m.checkpoint_rows += 1;
    expect(verifyManifestSignature(m, key.publicKeyPem)).toBe(false);
  });

  it('reads the object back and refuses to call a bad upload a success', async () => {
    s3.corruptGet = `witness/2026-08-17T03-00-00Z/witness.db`;
    await expect(backup()).rejects.toThrow(/read-back mismatch/);
  });

  it('fails loudly when the bucket refuses the write', async () => {
    s3.failPuts = 'AccessDenied';
    await expect(backup()).rejects.toThrow(/PUT .* failed: HTTP 500/);
  });

  it('leaves no staging directory behind after a failure', async () => {
    const before = readdirSync(tmpdir()).filter((f) => f.startsWith('witness-backup-')).length;
    s3.failPuts = 'AccessDenied';
    await expect(backup()).rejects.toThrow();
    expect(readdirSync(tmpdir()).filter((f) => f.startsWith('witness-backup-')).length).toBe(before);
  });

  it('never leaves the pointer naming a backup that is not fully there', async () => {
    await backup(new Date('2026-08-16T03:00:00Z'));
    const good = JSON.parse(s3.objects.get('witness/latest.json')!.toString()).stamp;
    s3.failGets = 'InternalError'; // the read-back fails on the next run
    await expect(backup(new Date('2026-08-17T03:00:00Z'))).rejects.toThrow();
    expect(JSON.parse(s3.objects.get('witness/latest.json')!.toString()).stamp).toBe(good);
  });
});

describe('the manifest records what a restore is checked against', () => {
  it('captures per-log heads, row counts and the witness key', async () => {
    const svc = new WitnessService(db, key);
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const logId = crypto.randomUUID();
    svc.register({ log_id: logId, signing_pubkey: publicKey.export({ type: 'spki', format: 'pem' }).toString() });
    const { canonicalJson } = await import('../src/canon.js');
    const { sign } = await import('node:crypto');
    const payload = { log_id: logId, index: 0, seq_from: 0, seq_to: 9, merkle_root: 'a'.repeat(64) };
    const r = svc.submit(logId, {
      index: 0, seq_from: 0, seq_to: 9, merkle_root: 'a'.repeat(64),
      signature: sign(null, Buffer.from(canonicalJson(payload), 'utf8'), privateKey).toString('base64'),
    });
    expect(r.ok).toBe(true);

    const out = await backup();
    const m = manifestFrom(s3, out.stamp);
    expect(m.checkpoint_rows).toBe(1);
    expect(m.logs[0]!.log_id).toBe(logId);
    expect(m.logs[0]!.last_idx).toBe(0);
    expect(m.logs[0]!.last_seq_to).toBe(9);
    expect(m.witness_pubkey_pem.trim()).toBe(key.publicKeyPem.trim());
  });
});

describe('retention', () => {
  it('keeps the newest N stamps and deletes both objects of the rest', async () => {
    for (let d = 1; d <= 5; d++) await backup(new Date(`2026-08-0${d}T03:00:00Z`), 3);
    const stamps = [...new Set([...s3.objects.keys()]
      .map((k) => /^witness\/([^/]+)\//.exec(k)?.[1]).filter(Boolean))].sort();
    expect(stamps).toEqual(['2026-08-03T03-00-00Z', '2026-08-04T03-00-00Z', '2026-08-05T03-00-00Z']);
    expect([...s3.objects.keys()].filter((k) => k.includes('2026-08-01'))).toEqual([]);
  });

  it('never deletes the pointer', async () => {
    for (let d = 1; d <= 4; d++) await backup(new Date(`2026-08-0${d}T03:00:00Z`), 1);
    expect(s3.objects.has('witness/latest.json')).toBe(true);
  });
});

describe('stampFor', () => {
  it('is filesystem- and key-safe and sorts chronologically', () => {
    const a = stampFor(new Date('2026-08-17T03:00:00.123Z'));
    const b = stampFor(new Date('2026-08-17T04:00:00.000Z'));
    expect(a).toBe('2026-08-17T03-00-00Z');
    expect(a < b).toBe(true);
    expect(a).not.toMatch(/[:.]/);
  });
});

describe('isOnDataVolume', () => {
  it('spots the configuration this whole change exists to remove', () => {
    expect(isOnDataVolume('/data/backups', '/data')).toBe(true);
    expect(isOnDataVolume('/data', '/data')).toBe(true);
    expect(isOnDataVolume('/mnt/elsewhere', '/data')).toBe(false);
    expect(isOnDataVolume('/data-other', '/data')).toBe(false);
  });
});

describe('the monitor', () => {
  const t = { ms: 1_700_000_000_000 };
  const mk = (o: Partial<ConstructorParameters<typeof BackupMonitor>[0]> = {}): BackupMonitor =>
    new BackupMonitor({ target: 's3:bucket', now: () => t.ms, log: () => {}, ...o });
  const outcome = (): BackupOutcome => ({
    stamp: 's', dbKey: 'k', manifestKey: 'm', bytes: 10, sha256: 'f'.repeat(64),
    readBack: 'full', pruned: [], target: 's3:bucket',
  });

  it('is red before the first backup completes', () => {
    const s = mk().status();
    expect(s.ok).toBe(false);
    expect(s.state).toBe('never_run');
  });

  it('goes green after a success and reports the age', () => {
    const m = mk();
    m.recordSuccess(outcome());
    t.ms += 3600_000;
    const s = m.status();
    expect(s.ok).toBe(true);
    expect(s.last_success_age_seconds).toBe(3600);
    t.ms -= 3600_000;
  });

  it('goes red when the last success ages past the limit', () => {
    const m = mk({ maxAgeSeconds: 100 });
    m.recordSuccess(outcome());
    t.ms += 101_000;
    expect(m.status().state).toBe('stale');
    t.ms -= 101_000;
  });

  it('goes red on a failure and counts consecutive ones', () => {
    const m = mk();
    m.recordSuccess(outcome());
    m.recordFailure('bucket on fire');
    m.recordFailure('bucket still on fire');
    const s = m.status();
    expect(s.state).toBe('failing');
    expect(s.consecutive_failures).toBe(2);
    expect(s.last_error).toBe('bucket still on fire');
  });

  it('reports no destination as red, and says what is missing', () => {
    const s = mk({ target: null, unconfiguredReason: 'missing AWS_ACCESS_KEY_ID' }).status();
    expect(s.ok).toBe(false);
    expect(s.state).toBe('not_configured');
    expect(s.detail).toContain('AWS_ACCESS_KEY_ID');
  });

  it('reports backups on the data volume as red even when they are succeeding', () => {
    const m = mk({ target: 'local:/data/backups', onDataVolume: true });
    m.recordSuccess(outcome());
    const s = m.status();
    expect(s.ok).toBe(false);
    expect(s.state).toBe('on_data_volume');
    expect(s.detail).toContain('losing the volume loses both');
  });

  it('logs a failure with alert: true', () => {
    const lines: Record<string, unknown>[] = [];
    mk({ log: (e) => lines.push(e) }).recordFailure('nope');
    expect(lines[0]!['msg']).toBe('BACKUP FAILED');
    expect(lines[0]!['alert']).toBe(true);
  });
});

describe('the dead-man heartbeat', () => {
  it('pings on success and /fail on failure', async () => {
    const seen: string[] = [];
    const m = new BackupMonitor({
      target: 's3:b', log: () => {}, heartbeatUrl: 'https://hc.example/abc',
      fetchImpl: (async (u: string) => { seen.push(u); return new Response('ok'); }) as unknown as typeof fetch,
    });
    m.recordSuccess({ stamp: 's', dbKey: 'k', manifestKey: 'm', bytes: 1, sha256: 'x', readBack: 'full', pruned: [], target: 's3:b' });
    m.recordFailure('boom');
    await new Promise((r) => setTimeout(r, 20));
    expect(seen).toEqual(['https://hc.example/abc', 'https://hc.example/abc/fail']);
  });

  it('does not take the service down when the alerting endpoint is unreachable', async () => {
    const logs: Record<string, unknown>[] = [];
    const m = new BackupMonitor({
      target: 's3:b', log: (e) => logs.push(e), heartbeatUrl: 'https://hc.example/abc',
      fetchImpl: (async () => { throw new Error('DNS is also down'); }) as unknown as typeof fetch,
    });
    m.recordSuccess({ stamp: 's', dbKey: 'k', manifestKey: 'm', bytes: 1, sha256: 'x', readBack: 'full', pruned: [], target: 's3:b' });
    await new Promise((r) => setTimeout(r, 20));
    expect(m.status().ok).toBe(true);
    expect(logs.some((l) => l['msg'] === 'heartbeat ping failed')).toBe(true);
  });
});

describe('scheduleBackups', () => {
  it('takes one immediately, so a broken destination announces itself at deploy time', async () => {
    const m = new BackupMonitor({ target: 's3:b', log: () => {} });
    const s = scheduleBackups(async () => { throw new Error('no such bucket'); }, m, 60_000);
    await new Promise((r) => setTimeout(r, 30));
    s.stop();
    expect(m.status().state).toBe('failing');
    expect(m.status().last_error).toBe('no such bucket');
  });

  it('does not let a slow run overlap the next tick', async () => {
    const m = new BackupMonitor({ target: 's3:b', log: () => {} });
    let running = 0; let maxConcurrent = 0; let runs = 0;
    const s = scheduleBackups(async () => {
      running++; runs++; maxConcurrent = Math.max(maxConcurrent, running);
      await new Promise((r) => setTimeout(r, 60));
      running--;
      return { stamp: 's', dbKey: 'k', manifestKey: 'm', bytes: 1, sha256: 'x', readBack: 'full' as const, pruned: [], target: 's3:b' };
    }, m, 10);
    await new Promise((r) => setTimeout(r, 200));
    s.stop();
    expect(maxConcurrent).toBe(1);
    expect(runs).toBeGreaterThan(1);
  });
});

describe('the endpoints', () => {
  const listen = async (monitor: BackupMonitor | null): Promise<{ url: string; close: () => Promise<void> }> => {
    const svc = new WitnessService(db, key);
    const app = createApp({ service: svc, log: () => {}, ...(monitor ? { backupStatus: () => monitor.status() } : {}) });
    await new Promise<void>((r) => app.listen(0, '127.0.0.1', r));
    const port = (app.address() as { port: number }).port;
    return { url: `http://127.0.0.1:${port}`, close: () => new Promise<void>((r) => { app.close(() => r()); }) };
  };

  it('/v1/backup-status answers 503 with a reason when backups are broken', async () => {
    const m = new BackupMonitor({ target: 's3:b', log: () => {} });
    m.recordFailure('bucket on fire');
    const srv = await listen(m);
    try {
      const res = await fetch(`${srv.url}/v1/backup-status`);
      expect(res.status).toBe(503);
      const body = await res.json() as { state: string; detail: string };
      expect(body.state).toBe('failing');
      expect(body.detail).toContain('bucket on fire');
    } finally { await srv.close(); }
  });

  it('/v1/backup-status answers 200 when they are fine', async () => {
    const m = new BackupMonitor({ target: 's3:b', log: () => {} });
    m.recordSuccess({ stamp: 's', dbKey: 'k', manifestKey: 'm', bytes: 1, sha256: 'x', readBack: 'full', pruned: [], target: 's3:b' });
    const srv = await listen(m);
    try { expect((await fetch(`${srv.url}/v1/backup-status`)).status).toBe(200); }
    finally { await srv.close(); }
  });

  it('/health stays 200 while backups are broken', async () => {
    // Deliberate. Fly restarts and then stops routing to a machine that fails
    // its health check. A late backup must never become an outage, because an
    // unreachable witness turns every customer's verify into exit 2.
    const m = new BackupMonitor({ target: null, log: () => {}, unconfiguredReason: 'nothing configured' });
    m.recordFailure('bucket on fire');
    const srv = await listen(m);
    try {
      expect((await fetch(`${srv.url}/health`)).status).toBe(200);
      expect((await fetch(`${srv.url}/v1/backup-status`)).status).toBe(503);
    } finally { await srv.close(); }
  });

  it('a process that runs no backups says so rather than looking healthy', async () => {
    const srv = await listen(null);
    try {
      const res = await fetch(`${srv.url}/v1/backup-status`);
      expect(res.status).toBe(503);
      expect((await res.json() as { state: string }).state).toBe('not_configured');
    } finally { await srv.close(); }
  });
});

describe('the signing key survives the volume', () => {
  it('loads from WITNESS_KEY_PEM as a raw PEM', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const k = loadKeyFromPem(pem);
    expect(k.publicKeyPem).toBe(createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString());
  });

  it('loads from WITNESS_KEY_PEM as base64, for secret stores that mangle newlines', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    expect(loadKeyFromPem(Buffer.from(pem).toString('base64')).publicKeyPem)
      .toBe(createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString());
  });

  it('prefers the secret over the volume, so a restored volume cannot change the identity', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const k = loadOrCreateKey(join(dataDir, 'nonexistent.pem'), { WITNESS_KEY_PEM: pem } as NodeJS.ProcessEnv);
    expect(k.publicKeyPem).toBe(createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString());
    expect(existsSync(join(dataDir, 'nonexistent.pem'))).toBe(false);
  });

  it('refuses to guess when the secret and the on-disk key disagree', () => {
    const onDisk = loadOrCreateKey(join(dataDir, 'disk.pem'), {} as NodeJS.ProcessEnv);
    const other = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    expect(() => loadOrCreateKey(join(dataDir, 'disk.pem'), { WITNESS_KEY_PEM: other } as NodeJS.ProcessEnv))
      .toThrow(/different keys/);
    expect(onDisk.publicKeyPem).toBeTruthy();
  });

  it('rejects a key of the wrong type rather than signing with it', () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
      .export({ type: 'pkcs8', format: 'pem' }).toString();
    expect(() => loadKeyFromPem(rsa)).toThrow(/expected ed25519/);
  });
});

describe('the local target', () => {
  it('round-trips and lists by prefix', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'witness-local-'));
    try {
      const t = localTarget(dir);
      await t.put('a/b/c.txt', Buffer.from('hello'));
      await t.put('other/d.txt', Buffer.from('x'));
      expect((await t.get('a/b/c.txt')).toString()).toBe('hello');
      expect((await t.list('a/')).map((o) => o.key)).toEqual(['a/b/c.txt']);
      await t.delete('a/b/c.txt');
      expect(await t.size('a/b/c.txt')).toBeNull();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
