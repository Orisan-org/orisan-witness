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

export function loadOrCreateKey(path: string): WitnessKey {
  const p = resolve(path);
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
