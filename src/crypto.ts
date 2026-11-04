const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function encodeJson(value: unknown): string {
  return bytesToBase64Url(encoder.encode(JSON.stringify(value)));
}

export function decodeJson<T>(value: string): T {
  return JSON.parse(decoder.decode(base64UrlToBytes(value))) as T;
}

/** `bytes` random bytes as base64url. */
export function randomToken(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return bytesToBase64Url(buf);
}

export async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value));
  return bytesToBase64Url(new Uint8Array(digest));
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}

/*
  An access-token secret is 32 random bytes as 64 hex characters, which is
  what `e9core setup-keys` and `openssl rand -hex 32` produce. Anyone who
  connects an Agent holds a token signed with it and can test guesses
  offline, so a value a person chose falls quickly. The shape check cannot
  prove a value is random; it refuses anything a person would type.
*/
const SECRET_SHAPE = /^[0-9a-f]{64}$/i;
// 64 random hex characters use fewer than 10 of the 16 digits about once in 10^12.
const SECRET_MIN_DISTINCT = 10;

/** Why `value` cannot be an access-token secret, or null when it can. */
export function secretProblem(value: unknown): string | null {
  if (typeof value !== 'string' || value === '') return 'is not set';
  if (!SECRET_SHAPE.test(value)) return 'is not 64 hex characters (32 random bytes)';
  if (new Set(value.toLowerCase()).size < SECRET_MIN_DISTINCT) return 'repeats too few characters to be random';
  return null;
}

const hmacKeys = new Map<string, Promise<CryptoKey>>();

function hmacKey(secret: string): Promise<CryptoKey> {
  let key = hmacKeys.get(secret);
  if (!key) {
    key = crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
      'sign',
      'verify',
    ]);
    hmacKeys.set(secret, key);
  }
  return key;
}

export async function hmacSign(secret: string, data: string): Promise<string> {
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), encoder.encode(data));
  return bytesToBase64Url(new Uint8Array(sig));
}

export async function hmacVerify(secret: string, data: string, signature: string): Promise<boolean> {
  let sig: Uint8Array;
  try {
    sig = base64UrlToBytes(signature);
  } catch {
    return false;
  }
  return crypto.subtle.verify('HMAC', await hmacKey(secret), sig as BufferSource, encoder.encode(data));
}

/** Constant-time comparison of two strings of any length. */
export function safeEqual(a: string, b: string): boolean {
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  let diff = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i += 1) diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  return diff === 0;
}
