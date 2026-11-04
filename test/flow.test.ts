import { describe, expect, it } from 'vitest';
import {
  CLAUDE_ID,
  CLAUDE_REDIRECT,
  CLI_ID,
  CLI_REDIRECT,
  DOMAIN,
  ISSUER,
  MCP,
  SECRET,
  SUB,
  agentRedirect,
  authorizePath,
  bearer,
  connect,
  consentFlowId,
  exchange,
  flowCookie,
  get,
  pkce,
  post,
  returnFromDelegate,
  setup,
  start,
} from './helpers';

describe('discovery', () => {
  it('serves authorization server metadata', async () => {
    const h = setup();
    const res = await h.agents.handle(get('/.well-known/oauth-authorization-server'));
    expect(res?.status).toBe(200);
    expect(await res!.json()).toEqual({
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/oauth/authorize`,
      token_endpoint: `${ISSUER}/oauth/token`,
      revocation_endpoint: `${ISSUER}/oauth/revoke`,
      scopes_supported: ['people:read', 'people:write'],
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
      revocation_endpoint_auth_methods_supported: ['none'],
      client_id_metadata_document_supported: true,
      authorization_response_iss_parameter_supported: true,
    });
  });

  it('serves protected resource metadata for a resource on this origin', async () => {
    const h = setup();
    const res = await h.agents.handle(get('/.well-known/oauth-protected-resource/mcp'));
    expect(await res!.json()).toEqual({
      resource: MCP,
      authorization_servers: [ISSUER],
      scopes_supported: ['people:read', 'people:write'],
      bearer_methods_supported: ['header'],
    });
  });

  it('never serves OpenID discovery', async () => {
    const h = setup();
    expect(await h.agents.handle(get('/.well-known/openid-configuration'))).toBeNull();
  });

  it('leaves other routes to the host', async () => {
    const h = setup();
    expect(await h.agents.handle(get('/mcp'))).toBeNull();
    expect(await h.agents.handle(get('/oauth/login'))).toBeNull();
  });

  it('answers a request with no credential with a pointer to the metadata', async () => {
    const h = setup();
    const result = await h.agents.authenticate(new Request(MCP));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('missing');
    expect(result.response.status).toBe(401);
    expect(result.response.headers.get('WWW-Authenticate')).toBe(
      `Bearer resource_metadata="${ISSUER}/.well-known/oauth-protected-resource/mcp"`,
    );
  });
});

describe('authorize: who may receive a code', () => {
  it('refuses a redirect URI the Agent did not register, without redirecting', async () => {
    const h = setup();
    const p = await pkce();
    const res = await h.agents.handle(
      get(authorizePath({ code_challenge: p.challenge, redirect_uri: 'https://attacker.example/cb' })),
    );
    expect(res?.status).toBe(400);
    expect(res!.headers.get('Location')).toBeNull();
    expect(await res!.text()).toContain('did not register');
  });

  it('refuses a client_id that is not registered, without redirecting', async () => {
    const h = setup();
    const p = await pkce();
    const res = await h.agents.handle(
      get(authorizePath({ code_challenge: p.challenge, client_id: 'anything', redirect_uri: 'https://attacker.example/cb' })),
    );
    expect(res?.status).toBe(400);
    expect(res!.headers.get('Location')).toBeNull();
  });

  it('requires PKCE S256', async () => {
    const h = setup();
    const res = await h.agents.handle(get(authorizePath({ code_challenge: 'x'.repeat(43), code_challenge_method: 'plain' })));
    const query = agentRedirect(res!);
    expect(query.get('error')).toBe('invalid_request');
    expect(query.get('state')).toBe('agent-state');
    expect(query.get('iss')).toBe(ISSUER);
  });

  it('refuses a resource that is not on this Domain', async () => {
    const h = setup();
    const p = await pkce();
    const res = await h.agents.handle(get(authorizePath({ code_challenge: p.challenge, resource: 'https://other.example/mcp' })));
    expect(agentRedirect(res!).get('error')).toBe('invalid_target');
  });

  it('refuses scopes this Domain does not have', async () => {
    const h = setup();
    const p = await pkce();
    const res = await h.agents.handle(get(authorizePath({ code_challenge: p.challenge, scope: 'admin' })));
    expect(agentRedirect(res!).get('error')).toBe('invalid_scope');
  });

  it('sends the person to Delegate as an ordinary Domain request', async () => {
    const h = setup();
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge });
    const q = s.delegateUrl.searchParams;
    expect(q.get('domain')).toBe(DOMAIN);
    expect(q.get('return_to')).toBe(`${ISSUER}/oauth/callback`);
    expect(q.get('min_level')).toBe('3');
    expect(q.get('fields')).toBe('email');
    expect(q.get('response_mode')).toBe('query');
    expect(q.get('nonce')).toBeTruthy();
    expect(s.cookie).toBe(`e9_agent_flow=${s.state}`);
  });

  it('accepts a loopback redirect on any port for a listed client', async () => {
    const h = setup();
    const p = await pkce();
    await start(h, {
      code_challenge: p.challenge,
      client_id: CLI_ID,
      redirect_uri: 'http://127.0.0.1:53111/callback',
    });
  });
});

describe('the whole flow', () => {
  it('connects, authenticates, and reports who and which scopes', async () => {
    const h = setup();
    const { tokens, html } = await connect(h);
    expect(html).toContain('Claude from claude.ai');
    expect(html).toContain('wants to act as you on www.example.com');
    expect(html).toContain('alex@example.com');
    expect(tokens.access_token.startsWith('e9agent_')).toBe(true);
    expect(tokens.refresh_token.startsWith('e9agentrefresh_')).toBe(true);
    expect(tokens.expires_in).toBe(3600);
    expect(tokens.scope).toBe('people:read people:write');

    const result = await h.agents.authenticate(bearer(tokens.access_token));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.credential.clientId).toBe(CLAUDE_ID);
    expect(result.credential.resource).toBe(MCP);
    expect(result.credential.scopes).toEqual(['people:read', 'people:write']);
    expect(result.credential.identity.sub).toBe(SUB);
    expect(result.credential.identity.level).toBe(3);
    expect(result.credential.identity.fields?.email).toBe('alex@example.com');
    expect(h.events.map((e) => e.type)).toEqual(['connection.created']);
  });

  it('lets the person approve fewer scopes than the Agent asked for', async () => {
    const h = setup();
    const { tokens } = await connect(h, { allow: ['people:read'] });
    expect(tokens.scope).toBe('people:read');
  });

  it('returns access_denied when the person cancels', async () => {
    const h = setup();
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge });
    const page = await returnFromDelegate(h, s);
    const res = await h.agents.handle(
      post('/oauth/consent', { flow: consentFlowId(await page.text()), decision: 'deny' }, flowCookie(page)!),
    );
    expect(agentRedirect(res!).get('error')).toBe('access_denied');
    expect(await h.store.findConnection(SUB, CLAUDE_ID, MCP, Math.floor(Date.now() / 1000))).toBeNull();
  });

  it('remembers consent for the same person and Agent', async () => {
    const h = setup();
    await connect(h);
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge, scope: 'people:read' });
    const res = await returnFromDelegate(h, s);
    const code = agentRedirect(res).get('code')!;
    const { body } = await exchange(h, code, p);
    expect(body.scope).toBe('people:read');
    expect(h.events.map((e) => e.type)).toEqual(['connection.created', 'connection.updated']);
  });

  it('asks again when the Agent wants more than was approved, and marks what is new', async () => {
    const h = setup();
    await connect(h, { scope: 'people:read' });
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge, scope: 'people:read people:write' });
    const res = await returnFromDelegate(h, s);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toMatch(/Add and change people <span class="new">New<\/span>/);
    expect(html).not.toMatch(/See people and their history <span class="new">/);
  });

  it('asks again after the Connection is revoked', async () => {
    const h = setup();
    const { tokens } = await connect(h);
    const [connection] = await h.agents.listConnections(SUB);
    expect(await h.agents.revokeConnection(connection.id, { sub: 'someone-else' })).toBe(false);
    expect(await h.agents.revokeConnection(connection.id, { sub: SUB })).toBe(true);
    expect((await h.agents.authenticate(bearer(tokens.access_token))).ok).toBe(false);
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge });
    expect((await returnFromDelegate(h, s)).status).toBe(200);
  });

  it('refuses an Identity Level below the minimum', async () => {
    const h = setup();
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge });
    const res = await returnFromDelegate(h, s, { level: 2 });
    const query = agentRedirect(res);
    expect(query.get('error')).toBe('access_denied');
    expect(query.get('error_description')).toContain('Identity Level 2');
  });

  it('refuses an Identity Token with the wrong nonce', async () => {
    const h = setup();
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge });
    const res = await returnFromDelegate(h, s, { nonce: 'replayed' });
    expect(agentRedirect(res).get('error')).toBe('access_denied');
  });

  it('refuses an Identity Token for another Domain', async () => {
    const h = setup();
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge });
    const res = await returnFromDelegate(h, s, { aud: 'evil.example', sub: 'evil.example:1' });
    expect(agentRedirect(res).get('error')).toBe('access_denied');
  });

  it('passes a Delegate error back to the Agent', async () => {
    const h = setup();
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge });
    const res = await h.agents.handle(get(`/oauth/callback?error=level_unavailable&state=${s.state}`, s.cookie));
    expect(agentRedirect(res!).get('error')).toBe('access_denied');
  });
});

describe('binding the flow to one browser', () => {
  it('refuses a callback from a browser that did not start the flow', async () => {
    const h = setup();
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge });
    const res = await returnFromDelegate(h, { ...s, cookie: '' });
    expect(res.status).toBe(400);
    expect(res.headers.get('Location')).toBeNull();
  });

  it('refuses a consent post without the flow cookie', async () => {
    const h = setup();
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge });
    const page = await returnFromDelegate(h, s);
    const res = await h.agents.handle(
      post('/oauth/consent', { flow: consentFlowId(await page.text()), decision: 'allow', scope: 'people:read' }),
    );
    expect(res?.status).toBe(400);
  });

  it('uses each callback state once', async () => {
    const h = setup();
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge });
    expect((await returnFromDelegate(h, s)).status).toBe(200);
    expect((await returnFromDelegate(h, s)).status).toBe(400);
  });

  it('expires an abandoned flow', async () => {
    const h = setup();
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge });
    h.tick(16 * 60);
    expect((await returnFromDelegate(h, s)).status).toBe(400);
  });

  it('sends pages that cannot be framed', async () => {
    const h = setup();
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge });
    const page = await returnFromDelegate(h, s);
    expect(page.headers.get('X-Frame-Options')).toBe('DENY');
    expect(page.headers.get('Content-Security-Policy')).toContain("frame-ancestors 'none'");
    expect(page.headers.getSetCookie()[0]).toMatch(/HttpOnly; SameSite=Lax; Secure/);
  });
});

describe('token endpoint', () => {
  async function codeFor(h: ReturnType<typeof setup>) {
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge });
    const page = await returnFromDelegate(h, s);
    const res = await h.agents.handle(
      post(
        '/oauth/consent',
        { flow: consentFlowId(await page.text()), decision: 'allow', scope: ['people:read'] },
        flowCookie(page)!,
      ),
    );
    return { p, code: agentRedirect(res!).get('code')! };
  }

  it('refuses a wrong verifier and burns the code', async () => {
    const h = setup();
    const { p, code } = await codeFor(h);
    const wrong = await exchange(h, code, { ...p, verifier: 'v'.repeat(43) });
    expect(wrong.body.error).toBe('invalid_grant');
    const right = await exchange(h, code, p);
    expect(right.body.error).toBe('invalid_grant');
  });

  it('uses each code once', async () => {
    const h = setup();
    const { p, code } = await codeFor(h);
    expect((await exchange(h, code, p)).res.status).toBe(200);
    expect((await exchange(h, code, p)).body.error).toBe('invalid_grant');
  });

  it('refuses a code for another client or redirect', async () => {
    const h = setup();
    const a = await codeFor(h);
    expect((await exchange(h, a.code, a.p, { client_id: CLI_ID })).body.error).toBe('invalid_grant');
    const b = await codeFor(h);
    expect((await exchange(h, b.code, b.p, { redirect_uri: `${CLAUDE_REDIRECT}x` })).body.error).toBe('invalid_grant');
  });

  it('expires codes after a minute', async () => {
    const h = setup();
    const { p, code } = await codeFor(h);
    h.tick(61);
    expect((await exchange(h, code, p)).body.error).toBe('invalid_grant');
  });

  it('rotates refresh tokens and ends the Connection when one is reused', async () => {
    const h = setup();
    const { tokens } = await connect(h);
    const refresh = (token: string) =>
      h.agents.handle(post('/oauth/token', { grant_type: 'refresh_token', refresh_token: token, client_id: CLAUDE_ID }));

    const first = await refresh(tokens.refresh_token);
    expect(first?.status).toBe(200);
    const next = (await first!.json()) as { access_token: string; refresh_token: string };
    expect(next.refresh_token).not.toBe(tokens.refresh_token);
    expect((await h.agents.authenticate(bearer(next.access_token))).ok).toBe(true);

    const replay = await refresh(tokens.refresh_token);
    expect(replay?.status).toBe(400);
    expect((await replay!.json()).error).toBe('invalid_grant');
    expect((await h.agents.authenticate(bearer(next.access_token))).ok).toBe(false);
    expect((await refresh(next.refresh_token))?.status).toBe(400);
    expect(h.events.at(-1)).toMatchObject({ type: 'connection.revoked', reason: 'refresh_reused' });
  });

  it('lets a refresh narrow scopes but never widen them', async () => {
    const h = setup();
    const { tokens } = await connect(h, { allow: ['people:read'] });
    const widen = await h.agents.handle(
      post('/oauth/token', { grant_type: 'refresh_token', refresh_token: tokens.refresh_token, scope: 'people:write' }),
    );
    expect((await widen!.json()).error).toBe('invalid_scope');
  });

  it('expires access tokens', async () => {
    const h = setup();
    const { tokens } = await connect(h);
    h.tick(3601);
    const result = await h.agents.authenticate(bearer(tokens.access_token));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('invalid_token');
    expect(result.response.headers.get('WWW-Authenticate')).toContain('error="invalid_token"');
  });

  it('ends the Connection after its maximum age, whatever the refresh tokens say', async () => {
    const h = setup({ connectionMaxAgeSeconds: 7200, refreshTokenTtlSeconds: 86400 });
    const { tokens } = await connect(h);
    h.tick(7201);
    const res = await h.agents.handle(post('/oauth/token', { grant_type: 'refresh_token', refresh_token: tokens.refresh_token }));
    expect((await res!.json()).error).toBe('invalid_grant');
  });

  it('answers CORS preflight', async () => {
    const h = setup();
    const res = await h.agents.handle(new Request(`${ISSUER}/oauth/token`, { method: 'OPTIONS' }));
    expect(res?.status).toBe(204);
    expect(res!.headers.get('Access-Control-Allow-Origin')).toBe('*');
  });
});

describe('authenticate', () => {
  it('rejects a forged or altered token', async () => {
    const h = setup();
    const { tokens } = await connect(h);
    const [body, sig] = tokens.access_token.split('.');
    const altered = `${body.slice(0, -2)}AA.${sig}`;
    expect((await h.agents.authenticate(bearer(altered))).ok).toBe(false);
    const other = setup({ secret: 'fedcba9876543210'.repeat(4) });
    expect((await other.agents.authenticate(bearer(tokens.access_token))).ok).toBe(false);
  });

  it('accepts tokens signed with an older secret during rotation', async () => {
    const h = setup();
    const { tokens } = await connect(h);
    const rotated = setup({ secret: ['00112233445566778899aabbccddeeff'.repeat(2), SECRET], store: h.store });
    expect((await rotated.agents.authenticate(bearer(tokens.access_token))).ok).toBe(true);
  });

  it('rejects a token for another resource', async () => {
    const h = setup({ resources: [MCP, `${ISSUER}/api`] });
    const { tokens } = await connect(h);
    expect((await h.agents.authenticate(bearer(tokens.access_token), MCP)).ok).toBe(true);
    expect((await h.agents.authenticate(bearer(tokens.access_token), `${ISSUER}/api`)).ok).toBe(false);
  });

  it('leaves other bearer credentials to the host', async () => {
    const h = setup();
    const result = await h.agents.authenticate(bearer('e9key_abc'));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe('other_credential');
  });

  it('builds a 403 for a missing scope', async () => {
    const h = setup();
    const res = h.agents.insufficientScope(['people:write']);
    expect(res.status).toBe(403);
    expect(res.headers.get('WWW-Authenticate')).toContain('error="insufficient_scope", scope="people:write"');
  });
});

describe('revocation endpoint', () => {
  it('ends the Connection for a refresh token', async () => {
    const h = setup();
    const { tokens } = await connect(h);
    const res = await h.agents.handle(post('/oauth/revoke', { token: tokens.refresh_token, client_id: CLAUDE_ID }));
    expect(res?.status).toBe(200);
    expect((await h.agents.authenticate(bearer(tokens.access_token))).ok).toBe(false);
    expect(h.events.at(-1)).toMatchObject({ type: 'connection.revoked', reason: 'agent_revoked' });
  });

  it('ends the Connection for an access token', async () => {
    const h = setup();
    const { tokens } = await connect(h);
    await h.agents.handle(post('/oauth/revoke', { token: tokens.access_token }));
    expect((await h.agents.authenticate(bearer(tokens.access_token))).ok).toBe(false);
  });

  it('answers 200 for an unknown token', async () => {
    const h = setup();
    expect((await h.agents.handle(post('/oauth/revoke', { token: 'nonsense' })))?.status).toBe(200);
  });

  it('refuses to revoke another client’s token', async () => {
    const h = setup();
    const { tokens } = await connect(h);
    const res = await h.agents.handle(post('/oauth/revoke', { token: tokens.refresh_token, client_id: CLI_ID }));
    expect(res?.status).toBe(400);
    expect((await h.agents.authenticate(bearer(tokens.access_token))).ok).toBe(true);
  });
});

describe('pre-registered client on loopback', () => {
  it('connects the CLI and remembers consent across ports', async () => {
    const h = setup();
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge, client_id: CLI_ID, redirect_uri: 'http://127.0.0.1:50001/callback' });
    const page = await returnFromDelegate(h, s);
    expect(await page.clone().text()).toContain('<strong>engine9 CLI</strong>');
    const res = await h.agents.handle(
      post(
        '/oauth/consent',
        { flow: consentFlowId(await page.text()), decision: 'allow', scope: ['people:read', 'people:write'] },
        flowCookie(page)!,
      ),
    );
    agentRedirect(res!, 'http://127.0.0.1:50001/callback');

    const p2 = await pkce();
    const s2 = await start(h, { code_challenge: p2.challenge, client_id: CLI_ID, redirect_uri: 'http://127.0.0.1:50999/callback' });
    const again = await returnFromDelegate(h, s2);
    expect(agentRedirect(again, 'http://127.0.0.1:50999/callback').get('code')).toBeTruthy();
    expect(CLI_REDIRECT).toBe('http://127.0.0.1/callback');
  });
});
