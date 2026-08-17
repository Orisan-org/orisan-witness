/**
 * A minimal S3-compatible client: PUT, GET, HEAD, DELETE, LIST, with AWS
 * SigV4 signing.
 *
 * Hand-rolled rather than @aws-sdk/client-s3 for the same reason the RFC 3161
 * request in the recorder is hand-rolled: this service's whole dependency list
 * is one native module, and a backup path is exactly the code you want to be
 * able to read in full. SigV4 is a published algorithm and the signature is
 * checked by the far end on every call, so a mistake here is loud, not silent.
 *
 * Path-style addressing (`<endpoint>/<bucket>/<key>`) because it works against
 * Tigris, MinIO, S3 itself and the test double without DNS games.
 */

import { createHash, createHmac } from 'node:crypto';

export interface S3Config {
  endpoint: string;
  bucket: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  /** Bounds every request. A backup that hangs is a backup that never fails. */
  timeoutMs?: number;
}

export interface S3Object { key: string; size: number; lastModified: string }

const EMPTY_SHA256 = createHash('sha256').update('').digest('hex');

/**
 * RFC 3986 encoding. `encodeURIComponent` leaves !'()* alone and AWS does not,
 * so an object key containing one of those would sign correctly here and be
 * rejected by the server. Cheap to get right, expensive to debug.
 */
export function uriEncode(s: string, encodeSlash: boolean): string {
  let out = '';
  for (const ch of Buffer.from(s, 'utf8')) {
    const c = String.fromCharCode(ch);
    if (/[A-Za-z0-9\-._~]/.test(c)) out += c;
    else if (c === '/') out += encodeSlash ? '%2F' : '/';
    else out += `%${ch.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return out;
}

function hmac(key: Buffer | string, data: string): Buffer {
  return createHmac('sha256', key).update(data, 'utf8').digest();
}

export interface SignedRequest { url: string; headers: Record<string, string> }

/**
 * Produce the signed headers for one request. Exported so a test can assert
 * the canonical request and string-to-sign against AWS's published example
 * vectors rather than against this function's own output.
 */
export function signV4(args: {
  cfg: S3Config;
  method: string;
  /** Absolute path including the bucket, already `/`-separated and unencoded. */
  path: string;
  query?: Record<string, string>;
  payloadSha256: string;
  now: Date;
  extraHeaders?: Record<string, string>;
}): SignedRequest & { canonicalRequest: string; stringToSign: string } {
  const { cfg, method, path, payloadSha256, now } = args;
  const amzDate = `${now.toISOString().replace(/[-:]/g, '').slice(0, 15)}Z`;
  const dateStamp = amzDate.slice(0, 8);
  const host = new URL(cfg.endpoint).host;

  const headers: Record<string, string> = {
    host,
    'x-amz-content-sha256': payloadSha256,
    'x-amz-date': amzDate,
    ...(args.extraHeaders ?? {}),
  };

  const sortedNames = Object.keys(headers).map((h) => h.toLowerCase()).sort();
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v.trim().replace(/\s+/g, ' ');
  const canonicalHeaders = sortedNames.map((n) => `${n}:${lower[n]}\n`).join('');
  const signedHeaders = sortedNames.join(';');

  const canonicalQuery = Object.entries(args.query ?? {})
    .map(([k, v]) => [uriEncode(k, true), uriEncode(v, true)] as const)
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join('&');

  const canonicalUri = path.split('/').map((seg) => uriEncode(seg, true)).join('/');
  const canonicalRequest = [
    method, canonicalUri, canonicalQuery, canonicalHeaders, signedHeaders, payloadSha256,
  ].join('\n');

  const scope = `${dateStamp}/${cfg.region}/s3/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    scope,
    createHash('sha256').update(canonicalRequest, 'utf8').digest('hex'),
  ].join('\n');

  const signing = hmac(hmac(hmac(hmac(`AWS4${cfg.secretAccessKey}`, dateStamp), cfg.region), 's3'), 'aws4_request');
  const signature = createHmac('sha256', signing).update(stringToSign, 'utf8').digest('hex');

  headers['authorization'] =
    `AWS4-HMAC-SHA256 Credential=${cfg.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const qs = canonicalQuery ? `?${canonicalQuery}` : '';
  return {
    url: `${cfg.endpoint.replace(/\/$/, '')}${canonicalUri}${qs}`,
    headers,
    canonicalRequest,
    stringToSign,
  };
}

/** Decode the five XML entities. List responses are XML and keys can contain them. */
function unxml(s: string): string {
  return s.replace(/&(amp|lt|gt|quot|apos);/g, (_, e: string) =>
    ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[e] ?? _));
}

export class S3Client {
  constructor(private readonly cfg: S3Config, private readonly now: () => Date = () => new Date()) {}

  get bucket(): string { return this.cfg.bucket; }
  get endpoint(): string { return this.cfg.endpoint; }

  private async call(
    method: string,
    key: string,
    opts: { body?: Buffer; query?: Record<string, string>; headers?: Record<string, string> } = {},
  ): Promise<Response> {
    const body = opts.body;
    const payloadSha256 = body ? createHash('sha256').update(body).digest('hex') : EMPTY_SHA256;
    const path = key ? `/${this.cfg.bucket}/${key}` : `/${this.cfg.bucket}`;
    const extra: Record<string, string> = { ...(opts.headers ?? {}) };
    if (body) extra['content-length'] = String(body.length);

    const signed = signV4({
      cfg: this.cfg, method, path, payloadSha256, now: this.now(),
      ...(opts.query ? { query: opts.query } : {}),
      extraHeaders: extra,
    });

    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), this.cfg.timeoutMs ?? 60_000);
    try {
      // `host` is set by fetch itself and rejected as a manual header.
      const { host: _host, ...sendable } = signed.headers;
      return await fetch(signed.url, {
        method,
        headers: sendable,
        ...(body ? { body: new Uint8Array(body) } : {}),
        signal: ac.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  private static async fail(what: string, res: Response): Promise<never> {
    const text = await res.text().catch(() => '');
    throw new Error(`${what} failed: HTTP ${res.status} ${res.statusText} ${text.slice(0, 400)}`.trim());
  }

  async put(key: string, body: Buffer, contentType = 'application/octet-stream'): Promise<void> {
    const res = await this.call('PUT', key, { body, headers: { 'content-type': contentType } });
    if (!res.ok) await S3Client.fail(`PUT ${key}`, res);
    await res.arrayBuffer();
  }

  async get(key: string): Promise<Buffer> {
    const res = await this.call('GET', key);
    if (!res.ok) await S3Client.fail(`GET ${key}`, res);
    return Buffer.from(await res.arrayBuffer());
  }

  async exists(key: string): Promise<boolean> {
    const res = await this.call('HEAD', key);
    await res.arrayBuffer().catch(() => undefined);
    if (res.status === 404) return false;
    if (!res.ok) await S3Client.fail(`HEAD ${key}`, res);
    return true;
  }

  async delete(key: string): Promise<void> {
    const res = await this.call('DELETE', key);
    // S3 delete is idempotent and answers 204 for a key that was never there.
    if (!res.ok && res.status !== 404) await S3Client.fail(`DELETE ${key}`, res);
    await res.arrayBuffer().catch(() => undefined);
  }

  async list(prefix: string): Promise<S3Object[]> {
    const out: S3Object[] = [];
    let token: string | undefined;
    do {
      const query: Record<string, string> = { 'list-type': '2', prefix, 'max-keys': '1000' };
      if (token) query['continuation-token'] = token;
      const res = await this.call('GET', '', { query });
      if (!res.ok) await S3Client.fail(`LIST ${prefix}`, res);
      const xml = await res.text();
      for (const m of xml.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g)) {
        const block = m[1]!;
        const key = /<Key>([\s\S]*?)<\/Key>/.exec(block)?.[1];
        if (!key) continue;
        out.push({
          key: unxml(key),
          size: Number.parseInt(/<Size>(\d+)<\/Size>/.exec(block)?.[1] ?? '0', 10),
          lastModified: /<LastModified>([\s\S]*?)<\/LastModified>/.exec(block)?.[1] ?? '',
        });
      }
      token = /<IsTruncated>true<\/IsTruncated>/.test(xml)
        ? /<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/.exec(xml)?.[1]
        : undefined;
    } while (token);
    return out;
  }
}

export interface RemoteConfigResult {
  client: S3Client | null;
  /** Why there is no client, for the status endpoint to report verbatim. */
  reason: string;
  prefix: string;
}

/**
 * Build a client from the environment.
 *
 * `fly storage create` injects AWS_* and BUCKET_NAME, so a Tigris bucket needs
 * no further configuration. The WITNESS_BACKUP_* names override, for anyone
 * pointing this at S3, R2 or MinIO instead.
 */
export function remoteFromEnv(env: NodeJS.ProcessEnv = process.env): RemoteConfigResult {
  const prefix = (env['WITNESS_BACKUP_PREFIX'] ?? 'witness').replace(/^\/+|\/+$/g, '');
  const endpoint = env['WITNESS_BACKUP_ENDPOINT'] ?? env['AWS_ENDPOINT_URL_S3'] ?? '';
  const bucket = env['WITNESS_BACKUP_BUCKET'] ?? env['BUCKET_NAME'] ?? '';
  const accessKeyId = env['AWS_ACCESS_KEY_ID'] ?? '';
  const secretAccessKey = env['AWS_SECRET_ACCESS_KEY'] ?? '';
  const region = env['WITNESS_BACKUP_REGION'] ?? env['AWS_REGION'] ?? 'auto';

  const missing = [
    ['endpoint', endpoint], ['bucket', bucket],
    ['AWS_ACCESS_KEY_ID', accessKeyId], ['AWS_SECRET_ACCESS_KEY', secretAccessKey],
  ].filter(([, v]) => !v).map(([n]) => n);

  if (missing.length) {
    return { client: null, prefix, reason: `off-box backups are not configured: missing ${missing.join(', ')}` };
  }
  return {
    client: new S3Client({ endpoint, bucket, region, accessKeyId, secretAccessKey }),
    prefix,
    reason: '',
  };
}
