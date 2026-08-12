#!/usr/bin/env node
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import { scheduleDailyBackup } from './backup.js';
import { WitnessDb } from './db.js';
import { loadOrCreateKey } from './keys.js';
import { WitnessService } from './service.js';
import { startServer } from './server.js';

const dbPath = resolve(process.env['WITNESS_DB'] ?? './data/witness.db');
const keyPath = resolve(process.env['WITNESS_KEY'] ?? './data/witness-signing.key');
const dataDir = dirname(dbPath);

const log = (e: Record<string, unknown>): void => { process.stdout.write(`${JSON.stringify(e)}\n`); };

// Create our own data directory. The Dockerfile also does this, but relying on
// the launcher means the service is broken anywhere else — and it crashed with
// "directory does not exist" the first time the built artefact was run outside
// the container.
mkdirSync(dataDir, { recursive: true });

const db = new WitnessDb(dbPath);
const key = loadOrCreateKey(keyPath);
const service = new WitnessService(db, key);

const backups = scheduleDailyBackup(db, dataDir, log);
const { port, close } = await startServer({ service, log });

log({ ts: new Date().toISOString(), msg: 'witness listening', port, db: dbPath });
// The public key is printed at boot so an operator can pin it from the logs
// without trusting a page that could be swapped later.
log({ ts: new Date().toISOString(), msg: 'witness public key', pem: service.publicKeyPem.trim() });

for (const sig of ['SIGTERM', 'SIGINT'] as const) {
  process.on(sig, () => {
    log({ ts: new Date().toISOString(), msg: 'shutting down', signal: sig });
    backups.stop();
    void close().then(() => { db.close(); process.exit(0); });
  });
}
