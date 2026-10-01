import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

/**
 * Cryptographic primitives for credential handling.
 *
 * Everything here is deliberately dependency-free and thin: in production the
 * data-encryption keys are unwrapped from a KMS, but the wire format and the
 * encryption-context binding stay identical between local dev and prod.
 */

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;
const AUTH_TAG_BYTES = 16;
const DATA_KEY_BYTES = 32;

export interface EnvelopeOptions {
  /** 32-byte data-encryption key (unwrapped from KMS in production). */
  dataKey: Buffer;
  /**
   * Additional authenticated data, e.g. `org_123:repository:repo_456`. Binding the
   * ciphertext to its tenant means a database-level mix-up cannot decrypt across
   * tenants — the tag check fails instead.
   */
  encryptionContext: string;
}

function assertDataKey(dataKey: Buffer): void {
  if (dataKey.length !== DATA_KEY_BYTES) {
    throw new Error(`Data key must be ${DATA_KEY_BYTES} bytes, received ${dataKey.length}`);
  }
}

/**
 * AES-256-GCM envelope encryption.
 * Wire format: [12-byte IV][16-byte auth tag][ciphertext]
 */
export function encryptEnvelope(plaintext: string | Buffer, options: EnvelopeOptions): Buffer {
  assertDataKey(options.dataKey);

  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, options.dataKey, iv);
  cipher.setAAD(Buffer.from(options.encryptionContext, 'utf8'));

  const body = Buffer.concat([
    cipher.update(typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext),
    cipher.final(),
  ]);

  return Buffer.concat([iv, cipher.getAuthTag(), body]);
}

export function decryptEnvelope(ciphertext: Buffer, options: EnvelopeOptions): Buffer {
  assertDataKey(options.dataKey);

  if (ciphertext.length < IV_BYTES + AUTH_TAG_BYTES) {
    throw new Error('Ciphertext is truncated');
  }

  const iv = ciphertext.subarray(0, IV_BYTES);
  const authTag = ciphertext.subarray(IV_BYTES, IV_BYTES + AUTH_TAG_BYTES);
  const body = ciphertext.subarray(IV_BYTES + AUTH_TAG_BYTES);

  const decipher = createDecipheriv(ALGORITHM, options.dataKey, iv);
  decipher.setAAD(Buffer.from(options.encryptionContext, 'utf8'));
  decipher.setAuthTag(authTag);

  // Throws on tamper, wrong key, or wrong encryption context.
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

export function decryptEnvelopeToString(ciphertext: Buffer, options: EnvelopeOptions): string {
  return decryptEnvelope(ciphertext, options).toString('utf8');
}

/** Decodes the base64 master key from configuration into raw bytes. */
export function parseMasterKey(base64Key: string): Buffer {
  const key = Buffer.from(base64Key, 'base64');
  assertDataKey(key);
  return key;
}

export function generateDataKey(): Buffer {
  return randomBytes(DATA_KEY_BYTES);
}

/**
 * Deterministic hash for storing API tokens. Tokens are high-entropy random
 * values, so a fast hash is appropriate and lets us look the row up by hash in a
 * single indexed query.
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export interface GeneratedApiToken {
  /** Returned to the user exactly once; never persisted. */
  token: string;
  prefix: string;
  tokenHash: string;
}

/** Generates a `sys_<random>` API token plus the fields we persist. */
export function generateApiToken(prefixLength = 8): GeneratedApiToken {
  const token = `sys_${randomBytes(32).toString('base64url')}`;
  return {
    token,
    prefix: token.slice(0, prefixLength),
    tokenHash: hashToken(token),
  };
}

export function signHmacSha256(payload: string | Buffer, secret: string): string {
  return createHmac('sha256', secret)
    .update(typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload)
    .digest('hex');
}

/**
 * Constant-time HMAC comparison for webhook signature verification.
 * Accepts the `sha256=<hex>` form used by GitHub as well as a bare hex digest.
 */
export function verifyHmacSha256(
  payload: string | Buffer,
  signatureHeader: string,
  secret: string,
): boolean {
  const provided = signatureHeader.includes('=')
    ? signatureHeader.slice(signatureHeader.indexOf('=') + 1)
    : signatureHeader;

  const expected = signHmacSha256(payload, secret);

  const expectedBuffer = Buffer.from(expected, 'utf8');
  const providedBuffer = Buffer.from(provided.trim(), 'utf8');

  if (expectedBuffer.length !== providedBuffer.length) return false;
  return timingSafeEqual(expectedBuffer, providedBuffer);
}

/** Constant-time comparison of two secrets of arbitrary length. */
export function constantTimeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(hashToken(left), 'utf8');
  const rightBuffer = Buffer.from(hashToken(right), 'utf8');
  return timingSafeEqual(leftBuffer, rightBuffer);
}
