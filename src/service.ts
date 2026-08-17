/**
 * W1.1 + W1.3 — witness service logic, independent of HTTP.
 *
 * The whole service is three verbs: remember a log's key, remember a
 * checkpoint, and tell anyone what the latest checkpoint was. The third is the
 * one that catches truncation, so it is public and unauthenticated: an auditor
 * who has to ask the operator's permission to read the head is not auditing.
 */

import { randomUUID } from 'node:crypto';

import { GENESIS_ROW_HASH, rowHash, type CheckpointRow, type WitnessDb } from './db.js';
import { isUsablePublicKey, signPayload, verifyWithPem, type WitnessKey } from './keys.js';

export interface RegisterRequest { log_id: string; signing_pubkey: string }
export interface SubmitRequest {
  index: number;
  seq_from: number;
  seq_to: number;
  merkle_root: string;
  signature: string;
}

export interface ServiceError { status: number; error: string; detail?: unknown }
export type Result<T> = { ok: true; value: T } | { ok: false; error: ServiceError };

const ok = <T>(value: T): Result<T> => ({ ok: true, value });
const err = <T>(status: number, error: string, detail?: unknown): Result<T> =>
  ({ ok: false, error: detail === undefined ? { status, error } : { status, error, detail } });

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX64 = /^[0-9a-f]{64}$/;

/**
 * The payload a CLIENT signs for a checkpoint submission.
 *
 * Must stay byte-identical to the recorder's side. It intentionally does NOT
 * include witnessed_at: the client cannot know when we will see it, and
 * letting the client assert our clock would defeat the point of an external
 * observer.
 */
export function clientSignedPayload(logId: string, r: SubmitRequest): unknown {
  return {
    log_id: logId,
    index: r.index,
    seq_from: r.seq_from,
    seq_to: r.seq_to,
    merkle_root: r.merkle_root,
  };
}

export interface Receipt {
  log_id: string;
  index: number;
  seq_from: number;
  seq_to: number;
  merkle_root: string;
  witnessed_at: string;
  witness_signature: string;
}

/** What the witness signs per stored checkpoint. Re-checked on restore. */
export function receiptSignedPayload(r: Omit<Receipt, 'witness_signature'>): unknown {
  return {
    log_id: r.log_id, index: r.index, seq_from: r.seq_from, seq_to: r.seq_to,
    merkle_root: r.merkle_root, witnessed_at: r.witnessed_at,
  };
}

export interface Head {
  log_id: string;
  latest_index: number;
  latest_seq_to: number;
  merkle_root: string;
  witnessed_at: string;
  conflict: boolean;
  conflict_count: number;
  witness_signature: string;
}

/** What the witness signs in a head. `conflict` is inside the signature so it cannot be stripped. */
export function headSignedPayload(h: Omit<Head, 'witness_signature'>): unknown {
  return {
    log_id: h.log_id,
    latest_index: h.latest_index,
    latest_seq_to: h.latest_seq_to,
    merkle_root: h.merkle_root,
    witnessed_at: h.witnessed_at,
    conflict: h.conflict,
    conflict_count: h.conflict_count,
  };
}

export class WitnessService {
  constructor(
    private readonly db: WitnessDb,
    private readonly key: WitnessKey,
    private readonly now: () => Date = () => new Date(),
  ) {}

  get publicKeyPem(): string { return this.key.publicKeyPem; }

  register(req: RegisterRequest): Result<{ log_id: string; registered_at: string }> {
    if (typeof req.log_id !== 'string' || !UUID_RE.test(req.log_id)) {
      return err(400, 'log_id must be a uuid');
    }
    if (typeof req.signing_pubkey !== 'string' || !req.signing_pubkey.includes('BEGIN PUBLIC KEY')) {
      return err(400, 'signing_pubkey must be an SPKI PEM');
    }
    // Reject a key we cannot parse now, rather than at the first submission
    // when the client has already started recording against it.
    if (!isUsablePublicKey(req.signing_pubkey)) return err(400, 'signing_pubkey is not a usable Ed25519 public key');

    const existing = this.db.getLog(req.log_id);
    if (existing) {
      if (existing.signing_pubkey.trim() !== req.signing_pubkey.trim()) {
        // Re-registering with a different key is the "re-seal and start over"
        // attack: it would orphan every checkpoint we already hold.
        return err(409, 'log_id already registered with a different signing key');
      }
      return ok({ log_id: existing.log_id, registered_at: existing.registered_at });
    }

    const registered_at = this.now().toISOString();
    this.db.insertLog({ log_id: req.log_id, signing_pubkey: req.signing_pubkey, registered_at });
    return ok({ log_id: req.log_id, registered_at });
  }

  submit(logId: string, req: SubmitRequest): Result<Receipt> {
    const log = this.db.getLog(logId);
    if (!log) return err(404, 'unknown log_id; register first');

    if (!Number.isSafeInteger(req.index) || req.index < 0) return err(400, 'index must be a non-negative integer');
    if (!Number.isSafeInteger(req.seq_from) || !Number.isSafeInteger(req.seq_to)) return err(400, 'seq range must be integers');
    if (typeof req.merkle_root !== 'string' || !HEX64.test(req.merkle_root)) return err(400, 'merkle_root must be sha256 hex');
    if (typeof req.signature !== 'string' || req.signature.length === 0) return err(400, 'signature required');
    // count >= 1: an empty checkpoint was a permanent integrity kill switch in
    // the recorder's own security review, and the witness must not store one.
    if (req.seq_to < req.seq_from) return err(400, 'seq_to must be >= seq_from');

    if (!verifyWithPem(log.signing_pubkey, clientSignedPayload(logId, req), req.signature)) {
      return err(401, 'signature does not verify against the registered key');
    }

    const last = this.db.lastCheckpoint(logId);
    const expectedIndex = last ? last.idx + 1 : 0;
    const expectedSeqFrom = last ? last.seq_to + 1 : 0;

    // A re-submission of an index we already hold. Identical content is a
    // harmless retry; different content is a fork, and must be recorded rather
    // than merely refused (Job 3).
    const existing = this.db.getCheckpoint(logId, req.index);
    if (existing) {
      const same =
        existing.merkle_root === req.merkle_root &&
        existing.seq_from === req.seq_from &&
        existing.seq_to === req.seq_to;
      if (same) {
        return ok({
          log_id: logId, index: existing.idx, seq_from: existing.seq_from, seq_to: existing.seq_to,
          merkle_root: existing.merkle_root, witnessed_at: existing.witnessed_at,
          witness_signature: existing.witness_signature,
        });
      }
      this.db.insertConflict({
        log_id: logId,
        idx: req.index,
        submitted_root: req.merkle_root,
        stored_root: existing.merkle_root,
        submitted_seq_from: req.seq_from,
        submitted_seq_to: req.seq_to,
        client_signature: req.signature,
        observed_at: this.now().toISOString(),
      });
      return err(409, 'checkpoint index already witnessed with different content', {
        index: req.index, stored_merkle_root: existing.merkle_root, submitted_merkle_root: req.merkle_root,
      });
    }

    if (req.index !== expectedIndex) {
      return err(409, `expected index ${expectedIndex}, got ${req.index}`, { expected_index: expectedIndex });
    }
    if (req.seq_from !== expectedSeqFrom) {
      return err(409, `expected seq_from ${expectedSeqFrom}, got ${req.seq_from}`, { expected_seq_from: expectedSeqFrom });
    }

    const witnessed_at = this.now().toISOString();
    const witness_signature = signPayload(this.key, receiptSignedPayload({
      log_id: logId, index: req.index, seq_from: req.seq_from, seq_to: req.seq_to,
      merkle_root: req.merkle_root, witnessed_at,
    }));

    const base: Omit<CheckpointRow, 'row_hash'> = {
      log_id: logId,
      idx: req.index,
      seq_from: req.seq_from,
      seq_to: req.seq_to,
      merkle_root: req.merkle_root,
      client_signature: req.signature,
      witnessed_at,
      witness_signature,
      prev_row_hash: last ? last.row_hash : GENESIS_ROW_HASH,
    };
    this.db.insertCheckpoint({ ...base, row_hash: rowHash(base) });

    return ok({
      log_id: logId, index: req.index, seq_from: req.seq_from, seq_to: req.seq_to,
      merkle_root: req.merkle_root, witnessed_at, witness_signature,
    });
  }

  head(logId: string): Result<Head> {
    const log = this.db.getLog(logId);
    if (!log) return err(404, 'unknown log_id');
    const last = this.db.lastCheckpoint(logId);
    const conflict_count = this.db.conflictCount(logId);

    const body: Omit<Head, 'witness_signature'> = {
      log_id: logId,
      latest_index: last ? last.idx : -1,
      latest_seq_to: last ? last.seq_to : -1,
      merkle_root: last ? last.merkle_root : '',
      // A log with no checkpoints still gets a signed, timestamped answer:
      // "nothing witnessed yet" is a fact an auditor needs to be able to trust.
      witnessed_at: last ? last.witnessed_at : log.registered_at,
      conflict: conflict_count > 0,
      conflict_count,
    };
    return ok({ ...body, witness_signature: signPayload(this.key, headSignedPayload(body)) });
  }

  newLogId(): string { return randomUUID(); }
}
