import { expect } from 'vitest';
import { createAgentCredentials } from '../src/agentCredentials';
import { bytesToBase64Url, encodeJson, randomToken, sha256Base64Url } from '../src/crypto';
import { memoryStore } from '../src/stores/memory';
import type { AgentCredentialEvent, AgentCredentialsOptions, AgentCredentialStore } from '../src/types';

export const ISSUER = 'https://www.example.com';
export const DOMAIN = 'www.example.com';
export const MCP = 'https://www.example.com/mcp';
export const DELEGATE = 'https://delegate.network';
export const CLAUDE_ID = 'https://claude.ai/oauth/mcp-client.json';
export const CLAUDE_REDIRECT = 'https://claude.ai/api/mcp/auth_callback';
export const CLI_ID = 'e9-cli';
export const CLI_REDIRECT = 'http://127.0.0.1/callback';
export const SUB = `${DOMAIN}:a1b2c3`;

const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
export const JWKS = { keys: [{ ...publicJwk, kty: 'EC', kid: 'test-key', alg: 'ES256', use: 'sig' }] };

/** An Identity Token signed the way Delegate signs one. */
export async function identityToken(claims: Record<string, unknown>): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const body = `${encodeJson({ alg: 'ES256', kid: 'test-key', typ: 'JWT' })}.${encodeJson({
    iss: DELEGATE,
    aud: DOMAIN,
    sub: SUB,
    level: 3,
    fields: { email: 'alex@example.com', email_verified: true },
    auth: { provider: 'google.com', amr: ['google'], auth_time: now - 60, two_factor: false },
    iat: now,
    exp: now + 300,
    jti: randomToken(8),
    ...claims,
  })}`;
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey,
    new TextEncoder().encode(body),
  );
  return `${body}.${bytesToBase64Url(new Uint8Array(signature))}`;
}

export function claudeMetadata(overrides: Record<string, unknown> = {}) {
  return {
    client_id: CLAUDE_ID,
    client_name: 'Claude',
    redirect_uris: [CLAUDE_REDIRECT],
    token_endpoint_auth_method: 'none',
    ...overrides,
  };
}

export interface Harness {
  agents: ReturnType<typeof createAgentCredentials>;
  store: AgentCredentialStore;
  events: AgentCredentialEvent[];
  fetched: string[];
  tick(seconds: number): void;
  metadata: Record<string, unknown>;
}

export function setup(overrides: Partial<AgentCredentialsOptions> = {}): Harness {
  let clock = Date.now();
  const events: AgentCredentialEvent[] = [];
  const fetched: string[] = [];
  const store = overrides.store ?? memoryStore();
  const harness: Harness = {
    store,
    events,
    fetched,
    metadata: claudeMetadata(),
    tick(seconds) {
      clock += seconds * 1000;
    },
    agents: null as never,
  };
  harness.agents = createAgentCredentials({
    issuer: ISSUER,
    resources: [MCP],
    secret: 's'.repeat(32),
    store,
    scopes: { 'people:read': 'See people and their history', 'people:write': 'Add and change people' },
    delegate: { jwks: JWKS },
    registration: { clients: [{ client_id: CLI_ID, client_name: 'engine9 CLI', redirect_uris: [CLI_REDIRECT] }] },
    fetch: async (input) => {
      const url = String(input);
      fetched.push(url);
      if (url === CLAUDE_ID) return new Response(JSON.stringify(harness.metadata), { status: 200 });
      return new Response('not found', { status: 404 });
    },
    now: () => clock,
    onEvent: (event) => {
      events.push(event);
    },
    ...overrides,
  });
  return harness;
}

export function get(path: string, cookie?: string): Request {
  return new Request(new URL(path, ISSUER), { headers: cookie ? { Cookie: cookie } : {} });
}

export function post(path: string, form: Record<string, string | string[]>, cookie?: string): Request {
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(form)) {
    for (const v of Array.isArray(value) ? value : [value]) body.append(key, v);
  }
  return new Request(new URL(path, ISSUER), {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(cookie ? { Cookie: cookie } : {}) },
    body: body.toString(),
  });
}

/** `name=value` of the flow cookie a response set, or null when it cleared it. */
export function flowCookie(response: Response): string | null {
  const set = response.headers.getSetCookie().find((c) => c.startsWith('e9_agent_flow='));
  if (!set) return null;
  const pair = set.split(';')[0];
  return pair === 'e9_agent_flow=' ? null : pair;
}

export interface Pkce {
  verifier: string;
  challenge: string;
}

export async function pkce(): Promise<Pkce> {
  const verifier = randomToken(48);
  return { verifier, challenge: await sha256Base64Url(verifier) };
}

export function authorizePath(params: Record<string, string>): string {
  return `/oauth/authorize?${new URLSearchParams({
    response_type: 'code',
    client_id: CLAUDE_ID,
    redirect_uri: CLAUDE_REDIRECT,
    code_challenge_method: 'S256',
    state: 'agent-state',
    resource: MCP,
    ...params,
  })}`;
}

export interface Started {
  cookie: string;
  state: string;
  nonce: string;
  delegateUrl: URL;
}

/** GET /oauth/authorize, expecting a redirect to Delegate. */
export async function start(h: Harness, params: Record<string, string>): Promise<Started> {
  const res = await h.agents.handle(get(authorizePath(params)));
  expect(res?.status).toBe(302);
  const delegateUrl = new URL(res!.headers.get('Location')!);
  expect(delegateUrl.origin + delegateUrl.pathname).toBe(`${DELEGATE}/identity/authorize`);
  const cookie = flowCookie(res!);
  expect(cookie).toBeTruthy();
  return {
    cookie: cookie!,
    state: delegateUrl.searchParams.get('state')!,
    nonce: delegateUrl.searchParams.get('nonce')!,
    delegateUrl,
  };
}

/** Delegate returning to the callback with a token for `claims`. */
export async function returnFromDelegate(h: Harness, s: Started, claims: Record<string, unknown> = {}): Promise<Response> {
  const token = await identityToken({ nonce: s.nonce, ...claims });
  const res = await h.agents.handle(
    get(`/oauth/callback?${new URLSearchParams({ delegate_token: token, state: s.state })}`, s.cookie),
  );
  return res!;
}

export function consentFlowId(page: string): string {
  const match = /name="flow" value="([^"]+)"/.exec(page);
  expect(match).toBeTruthy();
  return match![1];
}

/** Redirect back to the Agent; returns its query. */
export function agentRedirect(res: Response, redirectUri = CLAUDE_REDIRECT): URLSearchParams {
  expect(res.status).toBe(302);
  const location = new URL(res.headers.get('Location')!);
  expect(`${location.origin}${location.pathname}`).toBe(redirectUri);
  return location.searchParams;
}

export async function exchange(h: Harness, code: string, p: Pkce, extra: Record<string, string> = {}) {
  const res = (await h.agents.handle(
    post('/oauth/token', {
      grant_type: 'authorization_code',
      code,
      code_verifier: p.verifier,
      client_id: CLAUDE_ID,
      redirect_uri: CLAUDE_REDIRECT,
      resource: MCP,
      ...extra,
    }),
  ))!;
  return { res, body: (await res.json()) as Record<string, unknown> };
}

/** The whole first connection: authorize, sign in, allow, exchange. */
export async function connect(h: Harness, { scope = 'people:read people:write', allow }: { scope?: string; allow?: string[] } = {}) {
  const p = await pkce();
  const s = await start(h, { code_challenge: p.challenge, scope });
  const page = await returnFromDelegate(h, s);
  expect(page.status).toBe(200);
  const html = await page.text();
  const consent = await h.agents.handle(
    post(
      '/oauth/consent',
      { flow: consentFlowId(html), decision: 'allow', scope: allow ?? scope.split(' ') },
      flowCookie(page)!,
    ),
  );
  const query = agentRedirect(consent!);
  const { res, body } = await exchange(h, query.get('code')!, p);
  expect(res.status).toBe(200);
  return { tokens: body as { access_token: string; refresh_token: string; scope: string; expires_in: number }, html };
}

export function bearer(token: string, path = '/mcp'): Request {
  return new Request(new URL(path, ISSUER), { headers: { Authorization: `Bearer ${token}` } });
}
