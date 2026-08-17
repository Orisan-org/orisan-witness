/**
 * The third leg: a round-trip against a REAL S3 implementation.
 *
 * test/s3.test.ts proves the signing algorithm matches Amazon's published
 * vectors. test/fixtures/fake-s3.ts proves the client drives that algorithm
 * correctly. Neither proves a real bucket accepts what we send — only a real
 * bucket does. This runs when credentials are present and skips when they are
 * not, so CI stays hermetic and a human can still close the loop:
 *
 *   fly ssh console -a orisan-witness -C env    # or the values from `fly storage create`
 *   AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_ENDPOINT_URL_S3=... \
 *     BUCKET_NAME=... npx vitest run test/tigris.live.test.ts
 *
 * It writes only under a `livetest/` prefix and deletes what it wrote.
 */
import { describe, it, expect } from 'vitest';
import { randomUUID, createHash } from 'node:crypto';

import { remoteFromEnv } from '../src/s3.js';

const { client } = remoteFromEnv();
const live = client ? describe : describe.skip;

live('a real S3-compatible bucket', () => {
  const key = `livetest/${randomUUID()}.bin`;
  const body = Buffer.from(`orisan witness live check ${randomUUID()}`);

  it('accepts a signed PUT and returns the same bytes', async () => {
    await client!.put(key, body, 'application/octet-stream');
    const got = await client!.get(key);
    expect(createHash('sha256').update(got).digest('hex'))
      .toBe(createHash('sha256').update(body).digest('hex'));
  }, 60_000);

  it('lists the object under its prefix', async () => {
    const found = await client!.list('livetest/');
    expect(found.map((o) => o.key)).toContain(key);
    expect(found.find((o) => o.key === key)?.size).toBe(body.length);
  }, 60_000);

  it('reports a missing key as missing rather than throwing', async () => {
    expect(await client!.exists(`livetest/${randomUUID()}-absent`)).toBe(false);
    expect(await client!.exists(key)).toBe(true);
  }, 60_000);

  it('deletes, and delete is idempotent', async () => {
    await client!.delete(key);
    expect(await client!.exists(key)).toBe(false);
    await client!.delete(key); // must not throw
  }, 60_000);
});
