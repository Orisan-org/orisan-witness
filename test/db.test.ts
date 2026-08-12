/** W1.2 — storage: append-only, self-chained, and blind to content. */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { ALLOWED_CHECKPOINT_COLUMNS, GENESIS_ROW_HASH, WitnessDb, rowHash } from '../src/db.js';

let dir: string; let db: WitnessDb;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'wdb-')); db = new WitnessDb(join(dir, 'w.db')); });
afterEach(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });

const LOG = '11111111-2222-4333-8444-555555555555';

function seed(idx: number, from: number, to: number, root = 'a'.repeat(64)) {
  const last = db.lastCheckpoint(LOG);
  const base = {
    log_id: LOG, idx, seq_from: from, seq_to: to, merkle_root: root,
    client_signature: 'sig', witnessed_at: '2026-08-12T00:00:00.000Z',
    witness_signature: 'wsig', prev_row_hash: last ? last.row_hash : GENESIS_ROW_HASH,
  };
  db.insertCheckpoint({ ...base, row_hash: rowHash(base) });
}

describe('the witness cannot hold content — this is the selling point', () => {
  it('the checkpoints table has exactly the permitted columns', () => {
    expect(db.checkpointColumns().sort()).toEqual([...ALLOWED_CHECKPOINT_COLUMNS].sort());
  });

  it('no column name suggests event content', () => {
    const banned = /payload|content|args|argument|prompt|path|file|body|message|tool|name|input|output/i;
    for (const col of db.checkpointColumns()) {
      expect(col, `column "${col}" could carry content`).not.toMatch(banned);
    }
  });

  it('the whole schema mentions nothing content-shaped', () => {
    const sql = (db.raw().prepare("SELECT sql FROM sqlite_master WHERE type='table'").all() as { sql: string }[])
      .map((r) => r.sql).join('\n');
    for (const word of ['payload', 'content', 'arguments', 'prompt', 'filepath']) {
      expect(sql.toLowerCase()).not.toContain(word);
    }
  });
});

describe('append-only is enforced by the engine, not by discipline', () => {
  beforeEach(() => { db.insertLog({ log_id: LOG, signing_pubkey: 'pem', registered_at: 'now' }); seed(0, 0, 9); });

  it('UPDATE on checkpoints raises', () => {
    expect(() => db.raw().prepare("UPDATE checkpoints SET merkle_root='b' WHERE idx=0").run())
      .toThrow(/append-only/);
  });

  it('DELETE on checkpoints raises', () => {
    expect(() => db.raw().prepare('DELETE FROM checkpoints WHERE idx=0').run()).toThrow(/append-only/);
  });

  it('conflicts are append-only too', () => {
    db.insertConflict({
      log_id: LOG, idx: 0, submitted_root: 'b'.repeat(64), stored_root: 'a'.repeat(64),
      submitted_seq_from: 0, submitted_seq_to: 9, client_signature: 's', observed_at: 'now',
    });
    expect(() => db.raw().prepare('DELETE FROM conflicts').run()).toThrow(/append-only/);
  });

  it('a registered signing key cannot be changed', () => {
    expect(() => db.raw().prepare("UPDATE logs SET signing_pubkey='other' WHERE log_id=?").run(LOG))
      .toThrow(/cannot be changed/);
  });

  it('the same index cannot be inserted twice', () => {
    expect(() => seed(0, 10, 19)).toThrow();
  });
});

describe('the witness chains its own rows', () => {
  beforeEach(() => { db.insertLog({ log_id: LOG, signing_pubkey: 'pem', registered_at: 'now' }); });

  it('an intact chain reports no breaks', () => {
    seed(0, 0, 9); seed(1, 10, 19); seed(2, 20, 29);
    expect(db.verifyRowChain(LOG)).toEqual([]);
  });

  it('a row edited behind the triggers is detectable', () => {
    seed(0, 0, 9); seed(1, 10, 19);
    // Simulate an operator with raw file access defeating the triggers.
    db.raw().exec('DROP TRIGGER checkpoints_no_update');
    db.raw().prepare("UPDATE checkpoints SET merkle_root='c' WHERE idx=1").run();
    const breaks = db.verifyRowChain(LOG);
    expect(breaks.length).toBeGreaterThan(0);
    expect(breaks[0]!.idx).toBe(1);
  });

  it('the first row links to genesis', () => {
    seed(0, 0, 4);
    expect(db.lastCheckpoint(LOG)!.prev_row_hash).toBe(GENESIS_ROW_HASH);
  });
});
