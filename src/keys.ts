/**
 * The witness signing key.
 *
 * Ed25519 via node:crypto, published as SPKI PEM, because an auditor must be
 * able to check a head with openssl and no code of ours. The private key never
 * leaves this process and is never an API response.
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import {
  createPrivateKey, createPublicKey, generateKeyPairSync,
  sign as edSign, verify as edVerify, type KeyObject,
} from 'node:crypto';

import { canonicalJson } from './canon.js';

export interface WitnessKey {
  privateKey: KeyObject;
  publicKeyPem: string;
}

/**
 * Load the witness signing key, preferring an injected secret over the volume.
 *
 * WHY THE ENV PATH EXISTS. The key used to live only at /data/witness-signing.key,
 * on the same Fly volume as the database. Losing that volume lost the identity
 * as well as the history — and restoring the history under a NEW key produces a
 * witness that every client rejects with key_mismatch, because clients pin the
 * key at registration. So the backup work is worthless without somewhere else
 * for the key to live. WITNESS_KEY_PEM is that somewhere: a Fly secret, stored
 * off the machine, injected at boot, never written to disk.
 *
 * Accepts a PEM directly or base64 of one, because a private key with real
 * newlines is awkward to pass through a secrets CLI intact.
 *
 * If a secret and an on-disk key are both present and DIFFER, this throws.
 * Silently preferring one would change the witness's identity based on
 * deployment order, which is the failure this function exists to prevent.
 */
export function loadKeyFromPem(pem: string): WitnessKey {
  const text = pem.includes('BEGIN') ? pem : Buffer.from(pem.trim(), 'base64').toString('utf8');
  if (!text.includes('BEGIN')) throw new Error('WITNESS_KEY_PEM is neither a PEM nor base64 of one');
  const privateKey = createPrivateKey(text);
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw new Error(`WITNESS_KEY_PEM is ${privateKey.asymmetricKeyType ?? 'unknown'}, expected ed25519`);
  }
  return { privateKey, publicKeyPem: createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString() };
}

export function loadOrCreateKey(path: string, env: NodeJS.ProcessEnv = process.env): WitnessKey {
  const p = resolve(path);

  const secret = env['WITNESS_KEY_PEM'];
  if (secret && secret.trim()) {
    const fromSecret = loadKeyFromPem(secret);
    if (existsSync(p)) {
      const onDisk = createPublicKey(createPrivateKey(readFileSync(p, 'utf8')))
        .export({ type: 'spki', format: 'pem' }).toString();
      if (onDisk.trim() !== fromSecret.publicKeyPem.trim()) {
        throw new Error(
          `WITNESS_KEY_PEM and ${p} are different keys. Refusing to guess which identity this witness has; `
          + 'remove one of them.',
        );
      }
    }
    return fromSecret;
  }

  if (existsSync(p)) {
    const mode = statSync(p).mode & 0o777;
    if (process.platform !== 'win32' && (mode & 0o077) !== 0) {
      throw new Error(`witness key ${p} is mode ${mode.toString(8)}; must be owner-only (chmod 600)`);
    }
    const privateKey = createPrivateKey(readFileSync(p, 'utf8'));
    return { privateKey, publicKeyPem: createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString() };
  }
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), { mode: 0o600 });
  chmodSync(p, 0o600);
  return { privateKey, publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString() };
}

export function signPayload(key: WitnessKey, payload: unknown): string {
  return edSign(null, Buffer.from(canonicalJson(payload), 'utf8'), key.privateKey).toString('base64');
}

/** Can we parse this as a public key at all? Checked at registration. */
export function isUsablePublicKey(pem: string): boolean {
  try {
    const key = createPublicKey(pem);
    return key.asymmetricKeyType === 'ed25519';
  } catch {
    return false;
  }
}

/** Verify a client signature over a payload with their registered SPKI PEM. */
export function verifyWithPem(pubkeyPem: string, payload: unknown, signatureB64: string): boolean {
  try {
    return edVerify(
      null,
      Buffer.from(canonicalJson(payload), 'utf8'),
      createPublicKey(pubkeyPem),
      Buffer.from(signatureB64, 'base64'),
    );
  } catch {
    return false;
  }
}
