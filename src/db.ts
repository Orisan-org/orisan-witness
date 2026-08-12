/**
 * W1.2 — append-only storage.
 *
 * Two properties, both enforced by the database rather than by discipline:
 *
 * 1. INSERT only. UPDATE and DELETE on the checkpoint table raise. A witness
 *    whose operator can quietly edit rows is not a witness — it is a second
 *    copy of the operator's claim. Triggers are the enforcement because code
 *    that "never updates" is one careless patch away from doing so.
 *
 * 2. The witness chains its own rows. Each row carries the hash of the
 *    previous row for that log, so the witness cannot silently rewrite its own
 *    history either. The threat model names the operator as the attacker, but
 *    a customer relying on us is entitled to the same guarantee against us.
 *
 * What is deliberately NOT here: event content, tool arguments, payloads, file
 * paths, prompts. The witness sees an index, a range, a Merkle root and two
 * signatures. That is the whole point and there is a test asserting the schema
 * cannot hold anything else.
 */

import Database from 'better-sqlite3';
import { createHash } from 'node:crypto';

import { canonicalJson } from './canon.js';

export const GENESIS_ROW_HASH = '0'.repeat(64);

/**
 * Columns permitted on the checkpoints table.
 *
 * Asserted by a test. Adding a column that could carry content — a name, a
 * path, an argument — must be a deliberate act that breaks the build, not a
 * convenience someone slips in.
 */
export const ALLOWED_CHECKPOINT_COLUMNS = [
  'log_id', 'idx', 'seq_from', 'seq_to', 'merkle_root',
  'client_signature', 'witnessed_at', 'witness_signature', 'prev_row_hash', 'row_hash',
] as const;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS logs (
  log_id         TEXT PRIMARY KEY,
  signing_pubkey TEXT NOT NULL,
  registered_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
  log_id            TEXT    NOT NULL,
  idx               INTEGER NOT NULL,
  seq_from          INTEGER NOT NULL,
  seq_to            INTEGER NOT NULL,
  merkle_root       TEXT    NOT NULL,
  client_signature  TEXT    NOT NULL,
  witnessed_at      TEXT    NOT NULL,
  witness_signature TEXT    NOT NULL,
  prev_row_hash     TEXT    NOT NULL,
  row_hash          TEXT    NOT NULL,
  PRIMARY KEY (log_id, idx)
);
CREATE INDEX IF NOT EXISTS idx_checkpoints_log ON checkpoints(log_id, idx);

CREATE TABLE IF NOT EXISTS conflicts (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  log_id           TEXT    NOT NULL,
  idx              INTEGER NOT NULL,
  submitted_root   TEXT    NOT NULL,
  stored_root      TEXT    NOT NULL,
  submitted_seq_from INTEGER NOT NULL,
  submitted_seq_to   INTEGER NOT NULL,
  client_signature TEXT    NOT NULL,
  observed_at      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_conflicts_log ON conflicts(log_id);

-- Append-only, enforced by the engine.
CREATE TRIGGER IF NOT EXISTS checkpoints_no_update
BEFORE UPDATE ON checkpoints
BEGIN SELECT RAISE(ABORT, 'checkpoints are append-only: UPDATE is forbidden'); END;

CREATE TRIGGER IF NOT EXISTS checkpoints_no_delete
BEFORE DELETE ON checkpoints
BEGIN SELECT RAISE(ABORT, 'checkpoints are append-only: DELETE is forbidden'); END;

CREATE TRIGGER IF NOT EXISTS conflicts_no_update
BEFORE UPDATE ON conflicts
BEGIN SELECT RAISE(ABORT, 'conflicts are append-only: UPDATE is forbidden'); END;

CREATE TRIGGER IF NOT EXISTS conflicts_no_delete
BEFORE DELETE ON conflicts
BEGIN SELECT RAISE(ABORT, 'conflicts are append-only: DELETE is forbidden'); END;

-- A log's key is pinned at registration. Rotation is out of scope for W1, and
-- silently accepting a new key would defeat the pinning the client relies on.
CREATE TRIGGER IF NOT EXISTS logs_no_key_change
BEFORE UPDATE OF signing_pubkey ON logs
BEGIN SELECT RAISE(ABORT, 'a log signing key cannot be changed'); END;
`;

export interface LogRow {
  log_id: string;
  signing_pubkey: string;
  registered_at: string;
}

export interface CheckpointRow {
  log_id: string;
  idx: number;
  seq_from: number;
  seq_to: number;
  merkle_root: string;
  client_signature: string;
  witnessed_at: string;
  witness_signature: string;
  prev_row_hash: string;
  row_hash: string;
}

export interface ConflictRow {
  id: number;
  log_id: string;
  idx: number;
  submitted_root: string;
  stored_root: string;
  submitted_seq_from: number;
  submitted_seq_to: number;
  client_signature: string;
  observed_at: string;
}

/** The witness's own row chain: hash over the row's content plus its predecessor. */
export function rowHash(row: Omit<CheckpointRow, 'row_hash'>): string {
  return createHash('sha256')
    .update(canonicalJson({
      log_id: row.log_id,
      idx: row.idx,
      seq_from: row.seq_from,
      seq_to: row.seq_to,
      merkle_root: row.merkle_root,
      client_signature: row.client_signature,
      witnessed_at: row.witnessed_at,
      witness_signature: row.witness_signature,
      prev_row_hash: row.prev_row_hash,
    }), 'utf8')
    .digest('hex');
}

export class WitnessDb {
  private readonly db: Database.Database;

  constructor(path: string) {
    this.db = new Database(path);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.db.exec(SCHEMA);
  }

  /** Column names actually present, for the no-content-columns test. */
  checkpointColumns(): string[] {
    return (this.db.prepare('PRAGMA table_info(checkpoints)').all() as { name: string }[])
      .map((r) => r.name);
  }

  getLog(logId: string): LogRow | null {
    return (this.db.prepare('SELECT * FROM logs WHERE log_id = ?').get(logId) as LogRow | undefined) ?? null;
  }

  insertLog(row: LogRow): void {
    this.db.prepare(
      'INSERT INTO logs (log_id, signing_pubkey, registered_at) VALUES (@log_id, @signing_pubkey, @registered_at)',
    ).run(row);
  }

  lastCheckpoint(logId: string): CheckpointRow | null {
    return (this.db
      .prepare('SELECT * FROM checkpoints WHERE log_id = ? ORDER BY idx DESC LIMIT 1')
      .get(logId) as CheckpointRow | undefined) ?? null;
  }

  getCheckpoint(logId: string, idx: number): CheckpointRow | null {
    return (this.db
      .prepare('SELECT * FROM checkpoints WHERE log_id = ? AND idx = ?')
      .get(logId, idx) as CheckpointRow | undefined) ?? null;
  }

  insertCheckpoint(row: CheckpointRow): void {
    this.db.prepare(`
      INSERT INTO checkpoints
        (log_id, idx, seq_from, seq_to, merkle_root, client_signature,
         witnessed_at, witness_signature, prev_row_hash, row_hash)
      VALUES
        (@log_id, @idx, @seq_from, @seq_to, @merkle_root, @client_signature,
         @witnessed_at, @witness_signature, @prev_row_hash, @row_hash)
    `).run(row);
  }

  allCheckpoints(logId: string): CheckpointRow[] {
    return this.db.prepare('SELECT * FROM checkpoints WHERE log_id = ? ORDER BY idx ASC').all(logId) as CheckpointRow[];
  }

  insertConflict(row: Omit<ConflictRow, 'id'>): void {
    this.db.prepare(`
      INSERT INTO conflicts
        (log_id, idx, submitted_root, stored_root, submitted_seq_from, submitted_seq_to, client_signature, observed_at)
      VALUES
        (@log_id, @idx, @submitted_root, @stored_root, @submitted_seq_from, @submitted_seq_to, @client_signature, @observed_at)
    `).run(row);
  }

  conflictCount(logId: string): number {
    return (this.db.prepare('SELECT COUNT(*) AS n FROM conflicts WHERE log_id = ?').get(logId) as { n: number }).n;
  }

  conflicts(logId: string): ConflictRow[] {
    return this.db.prepare('SELECT * FROM conflicts WHERE log_id = ? ORDER BY id ASC').all(logId) as ConflictRow[];
  }

  /** Walk the witness's own row chain. Empty array means intact. */
  verifyRowChain(logId: string): { idx: number; reason: string }[] {
    const breaks: { idx: number; reason: string }[] = [];
    let prev = GENESIS_ROW_HASH;
    for (const row of this.allCheckpoints(logId)) {
      if (row.prev_row_hash !== prev) {
        breaks.push({ idx: row.idx, reason: `prev_row_hash ${row.prev_row_hash.slice(0, 12)}… != ${prev.slice(0, 12)}…` });
      }
      const { row_hash: stored, ...rest } = row;
      const recomputed = rowHash(rest);
      if (recomputed !== stored) breaks.push({ idx: row.idx, reason: 'row_hash does not match its content' });
      prev = stored;
    }
    return breaks;
  }

  close(): void { this.db.close(); }

  /** Escape hatch for tests that need to attempt a forbidden write. */
  raw(): Database.Database { return this.db; }
}
