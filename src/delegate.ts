import { verifyIdentityToken } from '@engine9/id';
import type { Identity, Jwks } from '@engine9/id';
import type { FetchLike } from './types';

const JWKS_TTL_MS = 60 * 60 * 1000;

/**
 * Verifies Identity Tokens for this Domain with Delegate's published keys.
 * Refetches the keys once when a token names a key id it has not seen.
 */
export function createIdentityVerifier({
  delegateUrl,
  domain,
  jwks,
  fetchImpl,
}: {
  delegateUrl: string;
  domain: string;
  jwks?: Jwks;
  fetchImpl: FetchLike;
}): (token: string, nonce: string) => Promise<Identity> {
  let cached: { keys: Jwks; at: number } | null = jwks ? { keys: jwks, at: Infinity } : null;

  async function keys(force: boolean): Promise<Jwks> {
    if (cached && !force && Date.now() - cached.at < JWKS_TTL_MS) return cached.keys;
    if (jwks) return jwks;
    const res = await fetchImpl(`${delegateUrl}/.well-known/jwks.json`);
    if (!res.ok) throw new Error(`Delegate keys answered ${res.status}`);
    const body = (await res.json()) as Jwks;
    cached = { keys: { keys: Array.isArray(body.keys) ? body.keys : [] }, at: Date.now() };
    return cached.keys;
  }

  return async (token, nonce) => {
    try {
      return await verifyIdentityToken({ token, jwks: await keys(false), domain, issuer: delegateUrl, nonce });
    } catch (error) {
      if (jwks || !(error instanceof Error) || !/No JWK for kid/.test(error.message)) throw error;
      return verifyIdentityToken({ token, jwks: await keys(true), domain, issuer: delegateUrl, nonce });
    }
  };
}
