import { describe, expect, it } from 'vitest';
import { metadataClientIdProblem, redirectUriMatches, redirectUriProblem } from '../src/clients';
import {
  CLAUDE_ID,
  CLAUDE_REDIRECT,
  ISSUER,
  SECRET,
  agentRedirect,
  authorizePath,
  claudeMetadata,
  consentFlowId,
  flowCookie,
  get,
  pkce,
  post,
  returnFromDelegate,
  setup,
  start,
} from './helpers';

describe('redirect URI rules', () => {
  it('allows https, loopback http, and native app schemes', () => {
    expect(redirectUriProblem('https://claude.ai/api/mcp/auth_callback')).toBeNull();
    expect(redirectUriProblem('http://127.0.0.1:3334/callback')).toBeNull();
    expect(redirectUriProblem('http://localhost/cb')).toBeNull();
    expect(redirectUriProblem('cursor://anysphere.cursor-retrieval/oauth/callback')).toBeNull();
  });

  it('refuses everything else', () => {
    expect(redirectUriProblem('http://example.com/cb')).toMatch(/not loopback/);
    expect(redirectUriProblem('javascript:alert(1)')).toMatch(/javascript/);
    expect(redirectUriProblem('data:text/html,hi')).toMatch(/data/);
    expect(redirectUriProblem('https://example.com/cb#x')).toMatch(/fragment/);
    expect(redirectUriProblem('https://u:p@example.com/cb')).toMatch(/credentials/);
    expect(redirectUriProblem('/relative')).toMatch(/absolute/);
  });

  it('matches exactly, except the port of a loopback redirect', () => {
    expect(redirectUriMatches('https://a.example/cb', 'https://a.example/cb')).toBe(true);
    expect(redirectUriMatches('https://a.example/cb', 'https://a.example/cb/')).toBe(false);
    expect(redirectUriMatches('https://a.example/cb', 'https://a.example:8443/cb')).toBe(false);
    expect(redirectUriMatches('http://127.0.0.1/cb', 'http://127.0.0.1:9000/cb')).toBe(true);
    expect(redirectUriMatches('http://127.0.0.1/cb', 'http://localhost:9000/cb')).toBe(false);
    expect(redirectUriMatches('http://127.0.0.1/cb', 'http://127.0.0.1:9000/other')).toBe(false);
  });
});

describe('Client ID Metadata Documents', () => {
  it('rules out client_ids that are not public https documents', () => {
    expect(metadataClientIdProblem(CLAUDE_ID)).toBeNull();
    expect(metadataClientIdProblem('http://claude.ai/client.json')).toMatch(/https/);
    expect(metadataClientIdProblem('https://claude.ai/')).toMatch(/no path/);
    expect(metadataClientIdProblem('https://localhost/client.json')).toMatch(/local/);
    expect(metadataClientIdProblem('https://10.0.0.5/client.json')).toMatch(/IP/);
    expect(metadataClientIdProblem('https://[::1]/client.json')).toMatch(/IP/);
    expect(metadataClientIdProblem('https://claude.ai/a/../client.json')).toBeNull(); // URL parsing removes dot segments
  });

  it('fetches the document once and caches it', async () => {
    const h = setup();
    const a = await pkce();
    await start(h, { code_challenge: a.challenge });
    await start(h, { code_challenge: a.challenge });
    expect(h.fetched.filter((u) => u === CLAUDE_ID)).toHaveLength(1);
  });

  it('refuses a document that names a different client_id', async () => {
    const h = setup();
    h.metadata = claudeMetadata({ client_id: 'https://evil.example/client.json' });
    const p = await pkce();
    const res = await h.agents.handle(get(authorizePath({ code_challenge: p.challenge })));
    expect(res?.status).toBe(400);
    expect(await res!.text()).toContain('different client_id');
  });

  it('refuses a confidential client', async () => {
    const h = setup();
    h.metadata = claudeMetadata({ token_endpoint_auth_method: 'client_secret_basic' });
    const p = await pkce();
    const res = await h.agents.handle(get(authorizePath({ code_challenge: p.challenge })));
    expect(res?.status).toBe(400);
  });

  it('refuses a document whose redirect is not allowed', async () => {
    const h = setup();
    h.metadata = claudeMetadata({ redirect_uris: ['http://claude.ai/cb'] });
    const p = await pkce();
    const res = await h.agents.handle(get(authorizePath({ code_challenge: p.challenge, redirect_uri: 'http://claude.ai/cb' })));
    expect(res?.status).toBe(400);
  });

  it('stops when the document drops the redirect URI mid-flow', async () => {
    let clock = Date.now();
    const h = setup({ now: () => clock });
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge });
    h.metadata = claudeMetadata({ redirect_uris: ['https://claude.ai/other'] });
    clock += 11 * 60 * 1000; // past the 10-minute cache
    const res = await returnFromDelegate(h, s);
    expect(res.status).toBe(400);
    expect(res.headers.get('Location')).toBeNull();
    expect(await res.text()).toContain('changed its registration');
  });

  it('can be turned off', async () => {
    const h = setup({ registration: { metadataDocuments: false } });
    const p = await pkce();
    const res = await h.agents.handle(get(authorizePath({ code_challenge: p.challenge })));
    expect(res?.status).toBe(400);
    expect(h.fetched).toHaveLength(0);
  });
});

describe('Dynamic Client Registration', () => {
  const register = (h: ReturnType<typeof setup>, body: unknown) =>
    h.agents.handle(
      new Request(`${ISSUER}/oauth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
    );

  it('is off by default', async () => {
    const h = setup();
    expect(await register(h, { redirect_uris: ['http://127.0.0.1/cb'] })).toBeNull();
    const meta = await (await h.agents.handle(get('/.well-known/oauth-authorization-server')))!.json();
    expect(meta.registration_endpoint).toBeUndefined();
  });

  it('registers a public client and warns on the consent screen that nothing about it is verified', async () => {
    const h = setup({ registration: { dynamic: true } });
    const meta = await (await h.agents.handle(get('/.well-known/oauth-authorization-server')))!.json();
    expect(meta.registration_endpoint).toBe(`${ISSUER}/oauth/register`);

    const res = await register(h, { client_name: 'Claude', redirect_uris: ['https://attacker.example/cb'] });
    expect(res?.status).toBe(201);
    const client = (await res!.json()) as { client_id: string };
    expect(client.client_id.startsWith('e9client_')).toBe(true);

    const p = await pkce();
    const s = await start(h, {
      code_challenge: p.challenge,
      client_id: client.client_id,
      redirect_uri: 'https://attacker.example/cb',
    });
    const page = await returnFromDelegate(h, s);
    const html = await page.text();
    expect(html).toContain('an app calling itself “Claude”');
    expect(html).toContain('no one has confirmed who made it');
    expect(html).toContain('attacker.example');

    const done = await h.agents.handle(
      post('/oauth/consent', { flow: consentFlowId(html), decision: 'allow', scope: 'people:read' }, flowCookie(page)!),
    );
    expect(agentRedirect(done!, 'https://attacker.example/cb').get('code')).toBeTruthy();
  });

  it('refuses unsafe registrations', async () => {
    const h = setup({ registration: { dynamic: true } });
    expect((await register(h, { redirect_uris: ['http://example.com/cb'] }))?.status).toBe(400);
    expect((await register(h, { redirect_uris: [] }))?.status).toBe(400);
    expect(
      (await register(h, { redirect_uris: ['https://a.example/cb'], token_endpoint_auth_method: 'client_secret_post' }))?.status,
    ).toBe(400);
    expect((await register(h, { redirect_uris: ['https://a.example/cb'], grant_types: ['client_credentials'] }))?.status).toBe(
      400,
    );
  });

  it('does not accept dynamic client_ids when registration is off', async () => {
    const h = setup({ registration: { dynamic: true } });
    const res = await register(h, { redirect_uris: [CLAUDE_REDIRECT] });
    const { client_id } = (await res!.json()) as { client_id: string };
    const off = setup({ store: h.store });
    const p = await pkce();
    const denied = await off.agents.handle(get(authorizePath({ code_challenge: p.challenge, client_id })));
    expect(denied?.status).toBe(400);
  });
});

describe('configuration', () => {
  it('rejects a short secret, a path on the issuer, and an unknown default scope', () => {
    expect(() => setup({ secret: 'short' })).toThrow(/64 hex characters/);
    expect(() => setup({ secret: 'this is a secret this is a secret' })).toThrow(/64 hex characters/);
    expect(() => setup({ secret: 'deadbeef'.repeat(8) })).toThrow(/too few characters/);
    expect(() => setup({ secret: [SECRET, 'I am god'] })).toThrow(/secret\[1\]/);
    expect(() => setup({ secret: SECRET.toUpperCase() })).not.toThrow();
    expect(() => setup({ issuer: 'https://www.example.com/app' })).toThrow(/origin/);
    expect(() => setup({ issuer: 'http://www.example.com' })).toThrow(/https/);
    expect(() => setup({ defaultScopes: ['admin'] })).toThrow(/unknown scope/);
    expect(() => setup({ scopes: { 'has space': 'x' } })).toThrow(/valid OAuth scope/);
  });
});
