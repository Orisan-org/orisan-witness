/**
 * W1.1 — the HTTP layer. Thin on purpose: routing, body limits, rate limiting
 * and structured logs. Every decision that matters lives in service.ts, where
 * it can be tested without a socket.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

import type { WitnessService } from './service.js';

export const MAX_BODY_BYTES = 16 * 1024;

export interface RateLimit {
  /** Writes allowed per log_id per window. */
  writesPerWindow: number;
  windowMs: number;
}

export const DEFAULT_RATE_LIMIT: RateLimit = { writesPerWindow: 120, windowMs: 60_000 };

export interface ServerOptions {
  service: WitnessService;
  rateLimit?: RateLimit;
  /** Structured log sink; defaults to stdout as one JSON object per line. */
  log?: (entry: Record<string, unknown>) => void;
  now?: () => number;
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const data = Buffer.from(`${JSON.stringify(body)}\n`, 'utf8');
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': data.length });
  res.end(data);
}

async function readBody(req: IncomingMessage): Promise<{ ok: true; value: unknown } | { ok: false; error: string }> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const c of req) {
    const chunk = c as Buffer;
    total += chunk.length;
    // Bounded before buffering: an unbounded reader is a free memory exhaustion.
    if (total > MAX_BODY_BYTES) return { ok: false, error: 'request body too large' };
    chunks.push(chunk);
  }
  if (total === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown };
  } catch {
    return { ok: false, error: 'body is not valid JSON' };
  }
}

/** Fixed-window limiter keyed by log_id. Writes only; reads are free by design. */
class Limiter {
  private readonly hits = new Map<string, { count: number; resetAt: number }>();
  constructor(private readonly cfg: RateLimit, private readonly now: () => number) {}

  allow(key: string): boolean {
    const t = this.now();
    const cur = this.hits.get(key);
    if (!cur || t >= cur.resetAt) {
      this.hits.set(key, { count: 1, resetAt: t + this.cfg.windowMs });
      return true;
    }
    if (cur.count >= this.cfg.writesPerWindow) return false;
    cur.count++;
    return true;
  }
}

export function createApp(opts: ServerOptions): Server {
  const { service } = opts;
  const now = opts.now ?? (() => Date.now());
  const limiter = new Limiter(opts.rateLimit ?? DEFAULT_RATE_LIMIT, now);
  const log = opts.log ?? ((e) => process.stdout.write(`${JSON.stringify(e)}\n`));

  return createServer((req, res) => {
    const started = now();
    const url = new URL(req.url ?? '/', 'http://witness.local');
    const path = url.pathname;
    const method = req.method ?? 'GET';

    const done = (status: number, extra: Record<string, unknown> = {}): void => {
      log({ ts: new Date().toISOString(), method, path, status, ms: now() - started, ...extra });
    };

    void (async () => {
      try {
        if (method === 'GET' && (path === '/health' || path === '/healthz')) {
          send(res, 200, { ok: true }); done(200); return;
        }

        if (method === 'GET' && path === '/v1/pubkey') {
          // Plain text would be friendlier for openssl, but a JSON API that
          // sometimes is not JSON is worse. The PEM is the value.
          send(res, 200, { algorithm: 'ed25519', public_key_pem: service.publicKeyPem });
          done(200); return;
        }

        if (method === 'POST' && path === '/v1/logs') {
          const body = await readBody(req);
          if (!body.ok) { send(res, 400, { error: body.error }); done(400); return; }
          const r = service.register(body.value as { log_id: string; signing_pubkey: string });
          if (!r.ok) { send(res, r.error.status, r.error); done(r.error.status, { reason: r.error.error }); return; }
          send(res, 200, r.value); done(200, { log_id: r.value.log_id }); return;
        }

        const submitMatch = /^\/v1\/logs\/([^/]+)\/checkpoints$/.exec(path);
        if (method === 'POST' && submitMatch) {
          const logId = decodeURIComponent(submitMatch[1]!);
          if (!limiter.allow(logId)) {
            send(res, 429, { error: 'rate limit exceeded for this log_id' });
            done(429, { log_id: logId }); return;
          }
          const body = await readBody(req);
          if (!body.ok) { send(res, 400, { error: body.error }); done(400); return; }
          const r = service.submit(logId, body.value as never);
          if (!r.ok) {
            send(res, r.error.status, r.error);
            // A 409 here is a fork attempt or a gap; both are worth a loud line.
            done(r.error.status, { log_id: logId, reason: r.error.error, alert: r.error.status === 409 });
            return;
          }
          send(res, 200, r.value); done(200, { log_id: logId, index: r.value.index }); return;
        }

        const headMatch = /^\/v1\/logs\/([^/]+)\/head$/.exec(path);
        if (method === 'GET' && headMatch) {
          const logId = decodeURIComponent(headMatch[1]!);
          const r = service.head(logId);
          if (!r.ok) { send(res, r.error.status, r.error); done(r.error.status); return; }
          send(res, 200, r.value);
          done(200, { log_id: logId, conflict: r.value.conflict }); return;
        }

        send(res, 404, { error: 'not found' }); done(404);
      } catch (e) {
        send(res, 500, { error: 'internal error' });
        done(500, { error: (e as Error).message });
      }
    })();
  });
}

export function startServer(
  opts: ServerOptions & { port?: number; host?: string },
): Promise<{ port: number; close: () => Promise<void> }> {
  const server = createApp(opts);
  const port = opts.port ?? Number.parseInt(process.env['PORT'] ?? '8080', 10);
  const host = opts.host ?? '0.0.0.0';
  return new Promise((resolve) => {
    server.listen(port, host, () => {
      const addr = server.address();
      resolve({
        port: typeof addr === 'object' && addr !== null ? addr.port : port,
        close: () => new Promise<void>((d) => { server.close(() => d()); }),
      });
    });
  });
}
