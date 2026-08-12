/**
 * W1.7 — daily backup.
 *
 * Uses SQLite's online backup API rather than copying the file, because
 * copying a WAL-mode database out from under a live writer can produce a
 * backup that will not open. Runs in-process on a timer; there is one instance
 * by design (see fly.toml), so there is no coordination to get wrong.
 *
 * Honest limitation, stated here and in the README: these backups land on the
 * same volume as the database. That protects against corruption and mistakes,
 * NOT against losing the volume. Off-box copies are a v2 item and until they
 * exist nobody should describe this as disaster recovery.
 */

import { existsSync, mkdirSync, readdirSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';

import type { WitnessDb } from './db.js';

export const BACKUP_DIRNAME = 'backups';
export const DEFAULT_RETAIN_DAYS = 14;

export function backupFileName(now: Date): string {
  return `witness-${now.toISOString().slice(0, 10)}.db`;
}

export async function runBackup(
  db: WitnessDb,
  dataDir: string,
  now: Date = new Date(),
  retainDays: number = DEFAULT_RETAIN_DAYS,
): Promise<string> {
  const dir = join(dataDir, BACKUP_DIRNAME);
  mkdirSync(dir, { recursive: true });
  const target = join(dir, backupFileName(now));

  // better-sqlite3's backup() is the online API: consistent against a live db.
  await db.raw().backup(target);

  // Retention, oldest first. A backup directory that grows forever fills the
  // volume and takes the service down with it.
  const files = readdirSync(dir)
    .filter((f) => /^witness-\d{4}-\d{2}-\d{2}\.db$/.test(f))
    .sort();
  while (files.length > retainDays) {
    const oldest = files.shift();
    if (oldest) rmSync(join(dir, oldest), { force: true });
  }
  return target;
}

export interface BackupSchedule { stop: () => void }

/** Start a daily backup timer. Returns a handle so tests and shutdown can stop it. */
export function scheduleDailyBackup(
  db: WitnessDb,
  dataDir: string,
  log: (e: Record<string, unknown>) => void,
  intervalMs = 24 * 60 * 60 * 1000,
): BackupSchedule {
  const tick = (): void => {
    void runBackup(db, dataDir)
      .then((path) => log({ ts: new Date().toISOString(), msg: 'backup written', path, bytes: statSync(path).size }))
      .catch((e: unknown) => log({ ts: new Date().toISOString(), msg: 'backup FAILED', error: (e as Error).message }));
  };
  // One immediately on boot: a service that has never been backed up is the
  // one most likely to need it.
  tick();
  const timer = setInterval(tick, intervalMs);
  timer.unref();
  return { stop: () => clearInterval(timer) };
}

export function latestBackup(dataDir: string): string | null {
  const dir = join(dataDir, BACKUP_DIRNAME);
  if (!existsSync(dir)) return null;
  const files = readdirSync(dir).filter((f) => f.endsWith('.db')).sort();
  return files.length ? join(dir, files[files.length - 1]!) : null;
}
