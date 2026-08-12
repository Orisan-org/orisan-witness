/** W1.1 + W1.3 — registration, submission, conflicts, heads. */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { generateKeyPairSync, createPublicKey, sign as edSign, verify as edVerify } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { canonicalJson } from '../src/canon.js';
import { WitnessDb } from '../src/db.js';
import { loadOrCreateKey } from '../src/keys.js';
import { WitnessService, clientSignedPayload, headSignedPayload, type SubmitRequest } from '../src/service.js';

let dir: string; let db: WitnessDb; let svc: WitnessService;
let clientPriv: ReturnType<typeof generateKeyPairSync<'ed25519'>>['privateKey'];
let clientPem: string;

const LOG = '11111111-2222-4333-8444-555555555555';
const root = (c: string) => c.repeat(64);

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'wsvc-'));
  db = new WitnessDb(join(dir, 'w.db'));
  svc = new WitnessService(db, loadOrCreateKey(join(dir, 'k.pem')), () => new Date('2026-08-12T10:00:00.000Z'));
  const kp = generateKeyPairSync('ed25519');
  clientPriv = kp.privateKey;
  clientPem = kp.publicKey.export({ type: 'spki', format: 'pem' }).toString();
});
afterEach(() => { db.close(); rmSync(dir, { recursive: true, force: true }); });

function submission(index: number, from: number, to: number, merkle = root('a')): SubmitRequest {
  const payload = clientSignedPayload(LOG, { index, seq_from: from, seq_to: to, merkle_root: merkle, signature: '' });
  const signature = edSign(null, Buffer.from(canonicalJson(payload), 'utf8'), clientPriv).toString('base64');
  return { index, seq_from: from, seq_to: to, merkle_root: merkle, signature };
}
const reg = () => svc.register({ log_id: LOG, signing_pubkey: clientPem });

describe('registration', () => {
  it('registers a log once and is idempotent for the same key', () => {
    const a = reg(); expect(a.ok).toBe(true);
    const b = reg(); expect(b.ok).toBe(true);
  });

  it('rejects a different key for an existing log_id (409)', () => {
    reg();
    const other = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const r = svc.register({ log_id: LOG, signing_pubkey: other });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.status).toBe(409);
  });

  it('rejects a non-uuid log_id and an unusable key', () => {
    expect(svc.register({ log_id: 'nope', signing_pubkey: clientPem }).ok).toBe(false);
    expect(svc.register({ log_id: LOG, signing_pubkey: 'BEGIN PUBLIC KEY garbage' }).ok).toBe(false);
  });
});

describe('submission', () => {
  beforeEach(() => { reg(); });

  it('accepts a well-formed first checkpoint and returns a signed receipt', () => {
    const r = svc.submit(LOG, submission(0, 0, 9));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.value.index).toBe(0);
    expect(edVerify(
      null,
      Buffer.from(canonicalJson({
        log_id: LOG, index: 0, seq_from: 0, seq_to: 9,
        merkle_root: root('a'), witnessed_at: r.value.witnessed_at,
      }), 'utf8'),
      createPublicKey(svc.publicKeyPem),
      Buffer.from(r.value.witness_signature, 'base64'),
    )).toBe(true);
  });

  it('rejects an unknown log', () => {
    const r = svc.submit('99999999-2222-4333-8444-555555555555', submission(0, 0, 9));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.status).toBe(404);
  });

  it('rejects a bad signature', () => {
    const s = submission(0, 0, 9);
    const r = svc.submit(LOG, { ...s, signature: Buffer.from('nope').toString('base64') });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.status).toBe(401);
  });

  it('rejects a signature over different content (the fields are bound)', () => {
    const s = submission(0, 0, 9, root('a'));
    const r = svc.submit(LOG, { ...s, merkle_root: root('b') });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.status).toBe(401);
  });

  it('enforces index contiguity: no gaps', () => {
    svc.submit(LOG, submission(0, 0, 9));
    const r = svc.submit(LOG, submission(2, 10, 19));
    expect(r.ok).toBe(false);
    if (!r.ok) { expect(r.error.status).toBe(409); expect(r.error.error).toMatch(/expected index 1/); }
  });

  it('enforces seq contiguity', () => {
    svc.submit(LOG, submission(0, 0, 9));
    const r = svc.submit(LOG, submission(1, 15, 19));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.error).toMatch(/expected seq_from 10/);
  });

  it('rejects an inverted range (count >= 1)', () => {
    const r = svc.submit(LOG, submission(0, 5, 4));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.status).toBe(400);
  });

  it('an identical re-submission is a harmless retry, not a conflict', () => {
    svc.submit(LOG, submission(0, 0, 9));
    const again = svc.submit(LOG, submission(0, 0, 9));
    expect(again.ok).toBe(true);
    expect(db.conflictCount(LOG)).toBe(0);
  });
});

describe('W1.3 — a fork must be visible, not merely refused', () => {
  beforeEach(() => { reg(); svc.submit(LOG, submission(0, 0, 9)); });

  it('a different root at the same index is 409 AND recorded', () => {
    const r = svc.submit(LOG, submission(0, 0, 9, root('b')));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.status).toBe(409);

    expect(db.conflictCount(LOG)).toBe(1);
    const c = db.conflicts(LOG)[0]!;
    expect(c.stored_root).toBe(root('a'));
    expect(c.submitted_root).toBe(root('b'));
  });

  it('the conflict surfaces on the head', () => {
    svc.submit(LOG, submission(0, 0, 9, root('b')));
    const h = svc.head(LOG);
    expect(h.ok).toBe(true);
    if (!h.ok) return;
    expect(h.value.conflict).toBe(true);
    expect(h.value.conflict_count).toBe(1);
  });

  it('the stored checkpoint is unchanged by the fork attempt', () => {
    svc.submit(LOG, submission(0, 0, 9, root('b')));
    expect(db.getCheckpoint(LOG, 0)!.merkle_root).toBe(root('a'));
  });
});

describe('head', () => {
  it('reports -1 for a registered log with no checkpoints', () => {
    reg();
    const h = svc.head(LOG);
    expect(h.ok).toBe(true);
    if (h.ok) { expect(h.value.latest_index).toBe(-1); expect(h.value.latest_seq_to).toBe(-1); }
  });

  it('tracks the latest checkpoint', () => {
    reg();
    svc.submit(LOG, submission(0, 0, 9));
    svc.submit(LOG, submission(1, 10, 19, root('c')));
    const h = svc.head(LOG);
    if (!h.ok) throw new Error('expected head');
    expect(h.value.latest_index).toBe(1);
    expect(h.value.latest_seq_to).toBe(19);
    expect(h.value.merkle_root).toBe(root('c'));
  });

  it('the signature covers the conflict flag, so it cannot be stripped', () => {
    reg();
    svc.submit(LOG, submission(0, 0, 9));
    svc.submit(LOG, submission(0, 0, 9, root('b'))); // fork
    const h = svc.head(LOG);
    if (!h.ok) throw new Error('expected head');

    const { witness_signature, ...body } = h.value;
    const verifies = (payload: unknown): boolean => edVerify(
      null, Buffer.from(canonicalJson(payload), 'utf8'),
      createPublicKey(svc.publicKeyPem), Buffer.from(witness_signature, 'base64'),
    );
    expect(verifies(headSignedPayload(body))).toBe(true);
    // Flip conflict to false and the signature must fail.
    expect(verifies(headSignedPayload({ ...body, conflict: false, conflict_count: 0 }))).toBe(false);
  });

  it('404s an unknown log', () => {
    const h = svc.head(LOG);
    expect(h.ok).toBe(false);
    if (!h.ok) expect(h.error.status).toBe(404);
  });
});
