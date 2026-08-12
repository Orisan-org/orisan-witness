/** W1.1 — the HTTP surface. */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { canonicalJson } from '../src/canon.js';
import { WitnessDb } from '../src/db.js';
import { loadOrCreateKey } from '../src/keys.js';
import { WitnessService, clientSignedPayload } from '../src/service.js';
import { MAX_BODY_BYTES, startServer } from '../src/server.js';

let dir: string; let db: WitnessDb; let base: string; let stop: () => Promise<void>;
const logs: Record<string, unknown>[] = [];
const kp = generateKeyPairSync('ed25519');
const clientPem = kp.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const LOG = '11111111-2222-4333-8444-555555555555';

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'wsrv-'));
  db = new WitnessDb(join(dir, 'w.db'));
  const svc = new WitnessService(db, loadOrCreateKey(join(dir, 'k.pem')));
  const s = await startServer({
    service: svc, port: 0, host: '127.0.0.1',
    log: (e) => logs.push(e),
    rateLimit: { writesPerWindow: 5, windowMs: 60_000 },
  });
  base = `http://127.0.0.1:${s.port}`;
  stop = s.close;
});
afterAll(async () => { await stop(); db.close(); rmSync(dir, { recursive: true, force: true }); });

const post = (p: string, body: unknown) =>
  fetch(`${base}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

function submission(index: number, from: number, to: number, merkle = 'a'.repeat(64)) {
  const payload = clientSignedPayload(LOG, { index, seq_from: from, seq_to: to, merkle_root: merkle, signature: '' });
  return {
    index, seq_from: from, seq_to: to, merkle_root: merkle,
    signature: edSign(null, Buffer.from(canonicalJson(payload), 'utf8'), kp.privateKey).toString('base64'),
  };
}

describe('endpoints', () => {
  it('health', async () => {
    expect((await fetch(`${base}/health`)).status).toBe(200);
  });

  it('publishes the witness public key as SPKI PEM', async () => {
    const r = await fetch(`${base}/v1/pubkey`);
    const b = (await r.json()) as { algorithm: string; public_key_pem: string };
    expect(b.algorithm).toBe('ed25519');
    expect(b.public_key_pem).toMatch(/^-----BEGIN PUBLIC KEY-----/);
  });

  it('register, submit, head', async () => {
    expect((await post('/v1/logs', { log_id: LOG, signing_pubkey: clientPem })).status).toBe(200);
    expect((await post(`/v1/logs/${LOG}/checkpoints`, submission(0, 0, 9))).status).toBe(200);

    const h = await (await fetch(`${base}/v1/logs/${LOG}/head`)).json() as { latest_index: number; conflict: boolean };
    expect(h.latest_index).toBe(0);
    expect(h.conflict).toBe(false);
  });

  it('reading a head needs no auth — an auditor must not need the operator', async () => {
    const r = await fetch(`${base}/v1/logs/${LOG}/head`, { headers: {} });
    expect(r.status).toBe(200);
  });

  it('a fork returns 409 and shows on the head', async () => {
    const r = await post(`/v1/logs/${LOG}/checkpoints`, submission(0, 0, 9, 'b'.repeat(64)));
    expect(r.status).toBe(409);
    const h = await (await fetch(`${base}/v1/logs/${LOG}/head`)).json() as { conflict: boolean; conflict_count: number };
    expect(h.conflict).toBe(true);
    expect(h.conflict_count).toBe(1);
  });

  it('unknown log heads 404', async () => {
    expect((await fetch(`${base}/v1/logs/99999999-2222-4333-8444-555555555555/head`)).status).toBe(404);
  });

  it('rejects an oversized body before buffering it', async () => {
    const r = await fetch(`${base}/v1/logs`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ log_id: LOG, signing_pubkey: 'x'.repeat(MAX_BODY_BYTES + 100) }),
    });
    expect(r.status).toBe(400);
  });

  it('rejects malformed JSON', async () => {
    const r = await fetch(`${base}/v1/logs`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{ nope',
    });
    expect(r.status).toBe(400);
  });

  it('rate limits writes per log_id but never reads', async () => {
    const other = '22222222-2222-4333-8444-555555555555';
    await post('/v1/logs', { log_id: other, signing_pubkey: clientPem });
    let limited = 0;
    for (let i = 0; i < 12; i++) {
      const r = await post(`/v1/logs/${other}/checkpoints`, { index: 0, seq_from: 0, seq_to: 1, merkle_root: 'a'.repeat(64), signature: 'x' });
      if (r.status === 429) limited++;
    }
    expect(limited).toBeGreaterThan(0);
    // Reads stay open even while writes are throttled.
    expect((await fetch(`${base}/v1/logs/${other}/head`)).status).toBe(200);
  });
});

describe('structured logs', () => {
  it('emits one object per request with status and duration', () => {
    expect(logs.length).toBeGreaterThan(0);
    const e = logs[0]!;
    expect(e).toHaveProperty('ts');
    expect(e).toHaveProperty('status');
    expect(e).toHaveProperty('ms');
  });

  it('marks a 409 as an alert so a fork attempt is loud', () => {
    expect(logs.some((e) => e['status'] === 409 && e['alert'] === true)).toBe(true);
  });

  it('never logs signature or merkle-root VALUES', () => {
    // The word "signature" may legitimately appear in a human-readable reason
    // ("signature does not verify..."). What must never appear is the material
    // itself: a 64-hex root or a base64 signature blob.
    const text = JSON.stringify(logs);
    expect(text).not.toMatch(/[0-9a-f]{64}/);
    expect(text).not.toMatch(/[A-Za-z0-9+/]{60,}={0,2}/);
  });

  it('logs the log_id but no request body', () => {
    const withBody = logs.filter((e) => 'signing_pubkey' in e || 'merkle_root' in e || 'signature' in e);
    expect(withBody).toEqual([]);
  });
});
