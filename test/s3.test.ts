/**
 * SigV4, pinned to AWS's own published examples.
 *
 * These four vectors come from the S3 "Signature Calculations for the
 * Authorization Header" documentation — inputs and expected signatures both.
 * Checking against our own output would only prove we are consistent; checking
 * against Amazon's proves we are correct, which is the only version of correct
 * that matters when the far end is the judge.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';

import { signV4, uriEncode, remoteFromEnv, type S3Config } from '../src/s3.js';

const CFG: S3Config = {
  endpoint: 'https://examplebucket.s3.amazonaws.com',
  bucket: 'examplebucket',
  region: 'us-east-1',
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
};
const WHEN = new Date('2013-05-24T00:00:00Z');
const EMPTY = createHash('sha256').update('').digest('hex');

const signatureOf = (r: { headers: Record<string, string> }): string =>
  /Signature=([0-9a-f]{64})/.exec(r.headers['authorization'] ?? '')![1]!;

describe('SigV4 against AWS published vectors', () => {
  it('GET Object with a Range header', () => {
    const r = signV4({
      cfg: CFG, method: 'GET', path: '/test.txt', payloadSha256: EMPTY, now: WHEN,
      extraHeaders: { range: 'bytes=0-9' },
    });
    expect(r.canonicalRequest).toBe(
      'GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\n'
      + `x-amz-content-sha256:${EMPTY}\nx-amz-date:20130524T000000Z\n\n`
      + `host;range;x-amz-content-sha256;x-amz-date\n${EMPTY}`,
    );
    expect(signatureOf(r)).toBe('f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41');
  });

  it('PUT Object with a key that needs escaping', () => {
    const body = Buffer.from('Welcome to Amazon S3.', 'utf8');
    const sha = createHash('sha256').update(body).digest('hex');
    expect(sha).toBe('44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072');
    const r = signV4({
      cfg: CFG, method: 'PUT', path: '/test$file.text', payloadSha256: sha, now: WHEN,
      extraHeaders: { date: 'Fri, 24 May 2013 00:00:00 GMT', 'x-amz-storage-class': 'REDUCED_REDUNDANCY' },
    });
    expect(r.canonicalRequest.split('\n')[1]).toBe('/test%24file.text');
    expect(signatureOf(r)).toBe('98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd');
  });

  it('GET Bucket Lifecycle — a valueless query parameter', () => {
    const r = signV4({
      cfg: CFG, method: 'GET', path: '/', query: { lifecycle: '' }, payloadSha256: EMPTY, now: WHEN,
    });
    expect(r.canonicalRequest.split('\n')[2]).toBe('lifecycle=');
    expect(signatureOf(r)).toBe('fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543');
  });

  it('List Objects — query parameters sorted, not source-ordered', () => {
    const r = signV4({
      cfg: CFG, method: 'GET', path: '/', query: { prefix: 'J', 'max-keys': '2' },
      payloadSha256: EMPTY, now: WHEN,
    });
    expect(r.canonicalRequest.split('\n')[2]).toBe('max-keys=2&prefix=J');
    expect(signatureOf(r)).toBe('34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7');
  });
});

describe('uriEncode', () => {
  it('escapes the characters encodeURIComponent leaves alone', () => {
    expect(uriEncode("!'()*", false)).toBe('%21%27%28%29%2A');
  });
  it('leaves unreserved characters and slashes alone in a path', () => {
    expect(uriEncode('a/b-c_d.e~f', false)).toBe('a/b-c_d.e~f');
  });
  it('escapes slashes when asked, for query components', () => {
    expect(uriEncode('a/b', true)).toBe('a%2Fb');
  });
  it('encodes non-ASCII as UTF-8 bytes', () => {
    expect(uriEncode('é', false)).toBe('%C3%A9');
  });
});

describe('remoteFromEnv', () => {
  it('reads the variables `fly storage create` injects, with no extra config', () => {
    const { client, reason } = remoteFromEnv({
      AWS_ENDPOINT_URL_S3: 'https://fly.storage.tigris.dev',
      BUCKET_NAME: 'orisan-witness-backups',
      AWS_ACCESS_KEY_ID: 'tid_x', AWS_SECRET_ACCESS_KEY: 'tsec_x',
    } as NodeJS.ProcessEnv);
    expect(reason).toBe('');
    expect(client?.bucket).toBe('orisan-witness-backups');
  });

  it('names exactly what is missing rather than failing vaguely', () => {
    const { client, reason } = remoteFromEnv({ BUCKET_NAME: 'b' } as NodeJS.ProcessEnv);
    expect(client).toBeNull();
    expect(reason).toContain('endpoint');
    expect(reason).toContain('AWS_ACCESS_KEY_ID');
    expect(reason).toContain('AWS_SECRET_ACCESS_KEY');
    expect(reason).not.toContain('bucket,');
  });
});
