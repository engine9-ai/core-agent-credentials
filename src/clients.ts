import type { AgentCredentialStore, FetchLike, PreRegisteredAgent } from './types';

/** Dynamic Client Registration ids start with this, so they never collide with a URL or a listed id. */
export const DYNAMIC_CLIENT_PREFIX = 'e9client_';

export interface ResolvedClient {
  client_id: string;
  /** Self-declared unless `kind` is `registered`. */
  client_name: string | null;
  redirect_uris: string[];
  /**
   * `registered`: listed by the host. `metadata`: a Client ID Metadata Document;
   * its host served the document, so the host is verified. `dynamic`: registered
   * itself through `/register`; nothing about it is verified.
   */
  kind: 'registered' | 'metadata' | 'dynamic';
}

const BLOCKED_SCHEMES = new Set(['javascript:', 'data:', 'vbscript:', 'file:', 'blob:', 'about:', 'ftp:', 'ws:', 'wss:']);
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);

function isLoopback(url: URL): boolean {
  return url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname.toLowerCase());
}

/**
 * Why a redirect URI cannot be registered, or null when it can: https, http on
 * loopback only, or a native app's own scheme (RFC 8252). No fragments.
 */
export function redirectUriProblem(uri: string): string | null {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return 'not an absolute URL';
  }
  if (url.hash) return 'has a fragment';
  if (url.username || url.password) return 'has credentials';
  const scheme = url.protocol.toLowerCase();
  if (BLOCKED_SCHEMES.has(scheme)) return `uses ${scheme}`;
  if (scheme === 'http:' && !isLoopback(url)) return 'uses http on a host that is not loopback';
  return null;
}

/**
 * Exact string match, except that a loopback redirect may use any port (RFC 8252
 * section 7.3): native apps pick a free port at run time.
 */
export function redirectUriMatches(registered: string, requested: string): boolean {
  if (registered === requested) return true;
  let a: URL;
  let b: URL;
  try {
    a = new URL(registered);
    b = new URL(requested);
  } catch {
    return false;
  }
  if (!isLoopback(a) || !isLoopback(b)) return false;
  return (
    a.hostname === b.hostname && a.pathname === b.pathname && a.search === b.search && !b.hash && !b.username && !b.password
  );
}

/** Rules for a `client_id` that is a Client ID Metadata Document URL. */
export function metadataClientIdProblem(clientId: string): string | null {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return 'not a URL';
  }
  if (url.protocol !== 'https:') return 'not https';
  if (url.hash || url.username || url.password) return 'has a fragment or credentials';
  if (url.pathname === '/' || url.pathname === '') return 'has no path';
  if (url.pathname.split('/').some((segment) => segment === '.' || segment === '..')) return 'has dot segments';
  const host = url.hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    return 'is a local host';
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.startsWith('[')) return 'is an IP address';
  return null;
}

const METADATA_MAX_BYTES = 10 * 1024;
const METADATA_TIMEOUT_MS = 5000;
const METADATA_CACHE_MS = 10 * 60 * 1000;

export interface ClientResolver {
  resolve(clientId: string): Promise<{ client: ResolvedClient } | { problem: string }>;
}

export function createClientResolver({
  clients,
  metadataDocuments,
  dynamic,
  store,
  fetchImpl,
  now,
}: {
  clients: PreRegisteredAgent[];
  metadataDocuments: boolean;
  dynamic: boolean;
  store: AgentCredentialStore;
  fetchImpl: FetchLike;
  now: () => number;
}): ClientResolver {
  const listed = new Map(clients.map((c) => [c.client_id, c]));
  const cache = new Map<string, { client: ResolvedClient; until: number }>();

  async function fetchMetadata(clientId: string): Promise<{ client: ResolvedClient } | { problem: string }> {
    const cached = cache.get(clientId);
    if (cached && cached.until > now()) return { client: cached.client };
    let res: Response;
    try {
      res = await fetchImpl(clientId, {
        headers: { Accept: 'application/json' },
        redirect: 'manual',
        signal: AbortSignal.timeout(METADATA_TIMEOUT_MS),
      });
    } catch {
      return { problem: 'its metadata document could not be fetched' };
    }
    if (res.status !== 200) return { problem: `its metadata document answered ${res.status}` };
    const text = await res.text();
    if (text.length > METADATA_MAX_BYTES) return { problem: 'its metadata document is too large' };
    let doc: Record<string, unknown>;
    try {
      doc = JSON.parse(text) as Record<string, unknown>;
    } catch {
      return { problem: 'its metadata document is not JSON' };
    }
    if (!doc || typeof doc !== 'object' || doc.client_id !== clientId) {
      return { problem: 'its metadata document names a different client_id' };
    }
    const auth = doc.token_endpoint_auth_method;
    if (auth !== undefined && auth !== 'none') {
      return { problem: `token_endpoint_auth_method ${String(auth)} is not supported (public clients only)` };
    }
    const uris = doc.redirect_uris;
    if (!Array.isArray(uris) || uris.length === 0 || !uris.every((u) => typeof u === 'string')) {
      return { problem: 'its metadata document has no redirect_uris' };
    }
    for (const uri of uris as string[]) {
      const problem = redirectUriProblem(uri);
      if (problem) return { problem: `redirect_uri ${uri} ${problem}` };
    }
    const client: ResolvedClient = {
      client_id: clientId,
      client_name: typeof doc.client_name === 'string' ? doc.client_name.slice(0, 100) : null,
      redirect_uris: uris as string[],
      kind: 'metadata',
    };
    cache.set(clientId, { client, until: now() + METADATA_CACHE_MS });
    return { client };
  }

  return {
    async resolve(clientId) {
      const fixed = listed.get(clientId);
      if (fixed) {
        return {
          client: {
            client_id: fixed.client_id,
            client_name: fixed.client_name,
            redirect_uris: fixed.redirect_uris,
            kind: 'registered',
          },
        };
      }
      if (clientId.startsWith(DYNAMIC_CLIENT_PREFIX)) {
        if (!dynamic) return { problem: 'dynamic registration is off on this Domain' };
        const stored = await store.getClient(clientId);
        if (!stored) return { problem: 'it is not registered' };
        return {
          client: {
            client_id: stored.client_id,
            client_name: stored.client_name,
            redirect_uris: stored.redirect_uris,
            kind: 'dynamic',
          },
        };
      }
      if (clientId.startsWith('https:')) {
        if (!metadataDocuments) return { problem: 'Client ID Metadata Documents are off on this Domain' };
        const problem = metadataClientIdProblem(clientId);
        if (problem) return { problem: `its client_id ${problem}` };
        return fetchMetadata(clientId);
      }
      return { problem: 'it is not registered' };
    },
  };
}
