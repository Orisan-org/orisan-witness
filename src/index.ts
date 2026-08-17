#!/usr/bin/env node
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import {
  isOnDataVolume, localTarget, runBackup, s3Target,
  type BackupOutcome, type BackupTarget,
} from './backup.js';
import { WitnessDb } from './db.js';
import { loadOrCreateKey } from './keys.js';
import { BackupMonitor, scheduleBackups, DEFAULT_INTERVAL_MS, DEFAULT_MAX_AGE_SECONDS } from './monitor.js';
import { formatReport, restore } from './restore.js';
import { remoteFromEnv } from './s3.js';
import { WitnessService } from './service.js';
import { startServer } from './server.js';

const log = (e: Record<string, unknown>): void => { process.stdout.write(`${JSON.stringify(e)}\n`); };
const now = (): string => new Date().toISOString();

const dbPath = resolve(process.env['WITNESS_DB'] ?? './data/witness.db');
const keyPath = resolve(process.env['WITNESS_KEY'] ?? './data/witness-signing.key');
const dataDir = dirname(dbPath);
const backupPrefix = (process.env['WITNESS_BACKUP_PREFIX'] ?? 'witness').replace(/^\/+|\/+$/g, '');

function flag(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
const has = (name: string): boolean => process.argv.includes(`--${name}`);

/**
 * Resolve where backups go.
 *
 * Off-box object storage if it is configured, and otherwise an explicitly
 * chosen local directory — never a silent fallback to the data volume. Falling
 * back would put the service back in the exact state this work removed while
 * still reporting healthy, which is worse than reporting nothing configured.
 */
function resolveTarget(): { target: BackupTarget | null; reason: string; onDataVolume: boolean } {
  const remote = remoteFromEnv();
  if (remote.client) return { target: s3Target(remote.client), reason: '', onDataVolume: false };

  const localDir = process.env['WITNESS_BACKUP_LOCAL_DIR'];
  if (localDir) {
    const t = localTarget(localDir);
    return { target: t, reason: '', onDataVolume: isOnDataVolume(t.root, dataDir) };
  }
  return { target: null, reason: remote.reason, onDataVolume: false };
}

async function cmdRestore(): Promise<number> {
  const { target } = resolveTarget();
  if (!target) {
    process.stderr.write('restore needs a backup source; set the AWS_*/BUCKET_NAME variables or WITNESS_BACKUP_LOCAL_DIR\n');
    return 2;
  }
  const to = flag('to');
  if (!to) {
    process.stderr.write('usage: orisan-witness restore --to <empty-dir> [--from <stamp|latest>] [--expect-pubkey <file>] [--force]\n');
    return 2;
  }
  const pubkeyFile = flag('expect-pubkey');
  const report = await restore({
    target, destDir: to, prefix: backupPrefix,
    stamp: flag('from') ?? 'latest',
    ...(pubkeyFile ? { expectPubkeyPem: readFileSync(pubkeyFile, 'utf8') } : {}),
    force: has('force'),
  });
  process.stdout.write(formatReport(report));
  return report.ok ? 0 : 1;
}

async function cmdBackupNow(): Promise<number> {
  const { target, reason } = resolveTarget();
  if (!target) { process.stderr.write(`${reason}\n`); return 2; }
  const db = new WitnessDb(dbPath);
  try {
    const out = await runBackup({ db, dbPath, key: loadOrCreateKey(keyPath), target, prefix: backupPrefix });
    process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
    return 0;
  } catch (e) {
    process.stderr.write(`BACKUP FAILED: ${(e as Error).message}\n`);
    return 1;
  } finally {
    db.close();
  }
}

async function cmdServe(): Promise<number> {
  mkdirSync(dataDir, { recursive: true });

  const db = new WitnessDb(dbPath);
  const key = loadOrCreateKey(keyPath);
  const service = new WitnessService(db, key);

  const { target, reason, onDataVolume } = resolveTarget();
  const monitor = new BackupMonitor({
    target: target?.describe ?? null,
    onDataVolume,
    unconfiguredReason: reason,
    maxAgeSeconds: Number.parseInt(process.env['WITNESS_BACKUP_MAX_AGE_SECONDS'] ?? '', 10) || DEFAULT_MAX_AGE_SECONDS,
    ...(process.env['WITNESS_BACKUP_HEARTBEAT_URL'] ? { heartbeatUrl: process.env['WITNESS_BACKUP_HEARTBEAT_URL'] } : {}),
    log,
  });

  const intervalMs = Number.parseInt(process.env['WITNESS_BACKUP_INTERVAL_MS'] ?? '', 10) || DEFAULT_INTERVAL_MS;
  const job = async (): Promise<BackupOutcome> => {
    if (!target) throw new Error(reason);
    return runBackup({ db, dbPath, key, target, prefix: backupPrefix });
  };
  const backups = scheduleBackups(job, monitor, intervalMs);

  const { port, close } = await startServer({ service, log, backupStatus: () => monitor.status() });

  log({ ts: now(), msg: 'witness listening', port, db: dbPath });
  log({ ts: now(), msg: 'witness public key', pem: service.publicKeyPem.trim() });
  log({
    ts: now(), msg: 'backup destination',
    target: target?.describe ?? null,
    on_data_volume: onDataVolume || undefined,
    heartbeat: Boolean(process.env['WITNESS_BACKUP_HEARTBEAT_URL']),
    // Not having a destination is a red state, not a note. Say so at boot,
    // where a deploy is being watched, rather than only on a status poll.
    alert: target ? undefined : true,
    detail: target ? undefined : reason,
  });

  for (const sig of ['SIGTERM', 'SIGINT'] as const) {
    process.on(sig, () => {
      log({ ts: now(), msg: 'shutting down', signal: sig });
      backups.stop();
      void close().then(() => { db.close(); process.exit(0); });
    });
  }
  return 0;
}

const command = process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : 'serve';

switch (command) {
  case 'serve': process.exitCode = await cmdServe(); break;
  case 'restore': process.exit(await cmdRestore());
  case 'backup-now': process.exit(await cmdBackupNow());
  case 'pubkey': {
    process.stdout.write(loadOrCreateKey(keyPath).publicKeyPem);
    process.exit(0);
  }
  default:
    process.stderr.write(`unknown command "${command}"; expected serve, restore, backup-now or pubkey\n`);
    process.exit(2);
}
