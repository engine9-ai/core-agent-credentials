import { decodeJson, encodeJson, hmacSign, hmacVerify, randomToken, sha256Hex } from './crypto';
import type { AgentIdentity } from './types';

/** Access tokens start with this. Grep for it to find a leaked one. */
export const ACCESS_TOKEN_PREFIX = 'e9agent_';
/** Refresh tokens start with this. */
export const REFRESH_TOKEN_PREFIX = 'e9agentrefresh_';

const ACCESS_TYP = 'e9.agent';

export interface AccessTokenPayload {
  typ: typeof ACCESS_TYP;
  /** Connection id. */
  cid: string;
  client_id: string;
  client_name: string | null;
  resource: string;
  scope: string;
  identity: AgentIdentity;
  connected_at: number;
  iat: number;
  exp: number;
}

export function isAccessToken(token: string): boolean {
  return token.startsWith(ACCESS_TOKEN_PREFIX) && !token.startsWith(REFRESH_TOKEN_PREFIX);
}

export function isRefreshToken(token: string): boolean {
  return token.startsWith(REFRESH_TOKEN_PREFIX);
}

/** `e9agent_<base64url json>.<base64url HMAC-SHA256>`. The signature covers the prefix. */
export async function signAccessToken(payload: Omit<AccessTokenPayload, 'typ'>, secret: string): Promise<string> {
  const body = `${ACCESS_TOKEN_PREFIX}${encodeJson({ typ: ACCESS_TYP, ...payload })}`;
  return `${body}.${await hmacSign(secret, body)}`;
}

/**
 * Checks the signature against every secret and the token type. Does not check
 * `exp`, the resource, or the Connection; the caller does.
 */
export async function readAccessToken(token: string, secrets: string[]): Promise<AccessTokenPayload | null> {
  if (!isAccessToken(token)) return null;
  const dot = token.lastIndexOf('.');
  if (dot <= ACCESS_TOKEN_PREFIX.length) return null;
  const body = token.slice(0, dot);
  const signature = token.slice(dot + 1);
  let valid = false;
  for (const secret of secrets) {
    if (await hmacVerify(secret, body, signature)) {
      valid = true;
      break;
    }
  }
  if (!valid) return null;
  let payload: AccessTokenPayload;
  try {
    payload = decodeJson<AccessTokenPayload>(body.slice(ACCESS_TOKEN_PREFIX.length));
  } catch {
    return null;
  }
  if (payload?.typ !== ACCESS_TYP || typeof payload.cid !== 'string' || typeof payload.exp !== 'number') return null;
  return payload;
}

export function newRefreshToken(): string {
  return `${REFRESH_TOKEN_PREFIX}${randomToken(32)}`;
}

export function hashRefreshToken(token: string): Promise<string> {
  return sha256Hex(token);
}
