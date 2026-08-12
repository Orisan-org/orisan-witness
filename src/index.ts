#!/usr/bin/env node
import { WitnessDb } from './db.js';
import { loadOrCreateKey } from './keys.js';
import { WitnessService } from './service.js';
import { startServer } from './server.js';

const dbPath = process.env['WITNESS_DB'] ?? './data/witness.db';
const keyPath = process.env['WITNESS_KEY'] ?? './data/witness-signing.key';

const db = new WitnessDb(dbPath);
const key = loadOrCreateKey(keyPath);
const service = new WitnessService(db, key);

const { port } = await startServer({ service });
process.stdout.write(`${JSON.stringify({
  ts: new Date().toISOString(), msg: 'witness listening', port, db: dbPath,
})}\n`);
