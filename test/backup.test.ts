/** W1.7 — daily backup. */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { BACKUP_DIRNAME, backupFileName, latestBackup, runBackup } from '../src/backup.js';
import { WitnessDb, GENESIS_ROW_HASH, rowHash } from '../src/db.js';

let dir: string; let db: WitnessDb;
const LOG = '11111111-2222-4333-8444-555555555555';

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'wbk-'));
  db = new WitnessDb(join(dir, 'witness.db'));
  db.insertLog({ log_id: LOG, signing_pubkey: 'pem', registered_at: 'now' });
  const base = {
    log_id: LOG, idx: 0, seq_from: 0, seq_to: 9, merkle_root: 'a'.repeat(64),
    client_signature: 's', witnessed_at: 'now', witness_signature: 'w', prev_row_hash: GENESIS_ROW_HASH,
  };
  db.insertCheckpoint({ ...base, row_hash: rowHash(base) });
});
afterEach(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });

describe('backup', () => {
  it('writes a readable copy containing the same rows', async () => {
    const path = await runBackup(db, dir, new Date('2026-08-12T00:00:00Z'));
    expect(existsSync(path)).toBe(true);

    const restored = new WitnessDb(path);
    try {
      expect(restored.lastCheckpoint(LOG)!.merkle_root).toBe('a'.repeat(64));
      // The restored copy must still be self-consistent.
      expect(restored.verifyRowChain(LOG)).toEqual([]);
    } finally { restored.close(); }
  });

  it('names backups by date and finds the latest', async () => {
    await runBackup(db, dir, new Date('2026-08-10T00:00:00Z'));
    await runBackup(db, dir, new Date('2026-08-11T00:00:00Z'));
    expect(latestBackup(dir)).toContain(backupFileName(new Date('2026-08-11T00:00:00Z')));
  });

  it('retains a bounded number, so the volume cannot fill', async () => {
    for (let d = 1; d <= 8; d++) {
      await runBackup(db, dir, new Date(`2026-08-0${d}T00:00:00Z`), 3);
    }
    const files = readdirSync(join(dir, BACKUP_DIRNAME));
    expect(files).toHaveLength(3);
    // The survivors are the newest.
    expect(files.sort()[0]).toBe('witness-2026-08-06.db');
  });

  it('the append-only triggers survive into the backup', async () => {
    const path = await runBackup(db, dir, new Date('2026-08-12T00:00:00Z'));
    const restored = new WitnessDb(path);
    try {
      expect(() => restored.raw().prepare('DELETE FROM checkpoints').run()).toThrow(/append-only/);
    } finally { restored.close(); }
  });
});
