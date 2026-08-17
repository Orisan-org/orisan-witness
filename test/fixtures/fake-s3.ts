/**
 * An in-memory S3-compatible server over a real socket.
 *
 * It RE-DERIVES the SigV4 signature of every request and rejects a mismatch
 * with 403, the same as the real thing. That is only worth something because
 * test/s3.test.ts pins `signV4` itself to Amazon's published vectors: the
 * vectors prove the algorithm is right, and this proves the client drives it
 * right — correct path, correct sorted query, correct payload digest. Neither
 * check is sufficient alone, and a live Tigris round-trip (test/tigris.live.test.ts)
 * is the third leg.
 *
 * The fault switches exist so the failure paths are exercised rather than
 * assumed: an upload that half-lands, a bucket that starts refusing writes.
 */
import { createHash } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';

import { signV4, type S3Config } from '../../src/s3.js';

export interface FakeS3 {
  url: string;
  bucket: string;
  config: Omit<S3Config, 'endpoint'> & { endpoint: string };
  objects: Map<string, Buffer>;
  /** Requests seen, for asserting the read-back actually happened. */
  calls: { method: string; key: string }[];
  failPuts: string | null;
  failGets: string | null;
  /** Serve this instead of the stored bytes, to simulate a silently bad upload. */
  corruptGet: string | null;
  stop: () => Promise<void>;
}

const ACCESS = 'AKIAFAKEFAKEFAKEFAKE';
const SECRET = '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';

function parseAmzDate(v: string): Date {
  const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(v);
  if (!m) throw new Error(`bad x-amz-date ${v}`);
  return new Date(Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!));
}

const xml = (s: string): string => s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]!));

export async function startFakeS3(bucket = 'test-bucket'): Promise<FakeS3> {
  const objects = new Map<string, Buffer>();
  const calls: { method: string; key: string }[] = [];
  const state = { failPuts: null as string | null, failGets: null as string | null, corruptGet: null as string | null };

  const server: Server = createServer((req, res) => {
    void (async () => {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const body = Buffer.concat(chunks);

      const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
      const method = req.method ?? 'GET';
      const decodedPath = decodeURIComponent(url.pathname);
      const key = decodedPath.startsWith(`/${bucket}/`) ? decodedPath.slice(bucket.length + 2) : '';

      const auth = String(req.headers['authorization'] ?? '');
      const signedHeaders = /SignedHeaders=([^,]+)/.exec(auth)?.[1]?.split(';') ?? [];
      const declared = String(req.headers['x-amz-content-sha256'] ?? '');

      // The payload digest must describe the bytes that actually arrived.
      const actual = createHash('sha256').update(body).digest('hex');
      if (declared !== actual) {
        res.writeHead(400).end(`<Error><Code>XAmzContentSHA256Mismatch</Code></Error>`);
        return;
      }

      const extra: Record<string, string> = {};
      for (const h of signedHeaders) {
        if (h === 'host' || h === 'x-amz-date' || h === 'x-amz-content-sha256') continue;
        extra[h] = String(req.headers[h] ?? '');
      }
      const query: Record<string, string> = {};
      for (const [k, v] of url.searchParams) query[k] = v;

      const expected = signV4({
        cfg: { endpoint: `http://${req.headers.host}`, bucket, region: 'auto', accessKeyId: ACCESS, secretAccessKey: SECRET },
        method, path: decodedPath, query, payloadSha256: declared,
        now: parseAmzDate(String(req.headers['x-amz-date'])),
        extraHeaders: extra,
      });
      if (expected.headers['authorization'] !== auth) {
        res.writeHead(403).end(`<Error><Code>SignatureDoesNotMatch</Code></Error>`);
        return;
      }

      calls.push({ method, key });

      if (method === 'GET' && !key) {
        const prefix = url.searchParams.get('prefix') ?? '';
        const items = [...objects.entries()].filter(([k]) => k.startsWith(prefix)).sort();
        res.writeHead(200, { 'content-type': 'application/xml' }).end(
          `<?xml version="1.0"?><ListBucketResult><IsTruncated>false</IsTruncated>${
            items.map(([k, v]) =>
              `<Contents><Key>${xml(k)}</Key><Size>${v.length}</Size><LastModified>1970-01-01T00:00:00.000Z</LastModified></Contents>`,
            ).join('')
          }</ListBucketResult>`,
        );
        return;
      }

      if (method === 'PUT') {
        if (state.failPuts) { res.writeHead(500).end(`<Error><Code>${xml(state.failPuts)}</Code></Error>`); return; }
        objects.set(key, body);
        res.writeHead(200, { etag: `"${actual}"` }).end();
        return;
      }
      if (method === 'GET' || method === 'HEAD') {
        if (state.failGets) { res.writeHead(500).end(`<Error><Code>${xml(state.failGets)}</Code></Error>`); return; }
        const stored = state.corruptGet === key ? Buffer.from('not the bytes you uploaded') : objects.get(key);
        if (!stored) { res.writeHead(404).end('<Error><Code>NoSuchKey</Code></Error>'); return; }
        res.writeHead(200, { 'content-length': String(stored.length) }).end(method === 'HEAD' ? undefined : stored);
        return;
      }
      if (method === 'DELETE') { objects.delete(key); res.writeHead(204).end(); return; }
      res.writeHead(405).end();
    })().catch((e: unknown) => { res.writeHead(500).end(String(e)); });
  });

  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  const endpoint = `http://127.0.0.1:${port}`;

  return {
    url: endpoint,
    bucket,
    config: { endpoint, bucket, region: 'auto', accessKeyId: ACCESS, secretAccessKey: SECRET },
    objects,
    calls,
    get failPuts() { return state.failPuts; }, set failPuts(v: string | null) { state.failPuts = v; },
    get failGets() { return state.failGets; }, set failGets(v: string | null) { state.failGets = v; },
    get corruptGet() { return state.corruptGet; }, set corruptGet(v: string | null) { state.corruptGet = v; },
    stop: () => new Promise<void>((r) => { server.close(() => r()); }),
  };
}
