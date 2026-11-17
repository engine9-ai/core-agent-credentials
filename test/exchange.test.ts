import { describe, expect, it } from 'vitest';
import { ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT } from '../src/tokens';
import type { AgentCredential, AuthorizationDetail } from '../src/types';
import { CLAUDE_ID, CLI_ID, ISSUER, MCP, bearer, connect, post, setup } from './helpers';

const API = 'https://www.example.com/v1';

/** A host that approves `window` details itself, the way an app keeps its own approvals. */
function host() {
  const approvals = new Map<string, { until: number; sub: string; clientId: string }>();
  const seen: { detail: AuthorizationDetail; credential: AgentCredential }[] = [];
  const revoked: string[] = [];
  const h = setup({
    resources: [MCP, API],
    authorizationDetails: {
      window: {
        check(detail, credential) {
          seen.push({ detail, credential });
          const a = approvals.get(String(detail.id));
          if (!a || a.sub !== credential.identity.sub || a.clientId !== credential.clientId) return null;
          return a.until;
        },
        revoke(detail) {
          revoked.push(String(detail.id));
          approvals.delete(String(detail.id));
        },
      },
    },
  });
  const nowS = () => Math.floor(Date.now() / 1000);
  return { h, approvals, seen, revoked, nowS };
}

const form = (subject: string, extra: Record<string, string> = {}) => ({
  grant_type: TOKEN_EXCHANGE_GRANT,
  subject_token: subject,
  subject_token_type: ACCESS_TOKEN_TYPE,
  resource: API,
  authorization_details: JSON.stringify([{ type: 'window', id: 'w1' }]),
  ...extra,
});
async function exchange(h: ReturnType<typeof setup>, fields: Record<string, string>) {
  const res = (await h.agents.handle(post('/oauth/token', fields)))!;
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

describe('token exchange (RFC 8693) with authorization_details (RFC 9396)', () => {
  it('is off, and not advertised, until the host names a detail type', async () => {
    const h = setup();
    expect(h.agents.authorizationServerMetadata().grant_types_supported).not.toContain(TOKEN_EXCHANGE_GRANT);
    expect(h.agents.authorizationServerMetadata().authorization_details_types_supported).toBeUndefined();
    const { tokens } = await connect(h);
    expect((await exchange(h, form(tokens.access_token, { resource: MCP }))).body.error).toBe('unsupported_grant_type');
    const t = host();
    expect(t.h.agents.authorizationServerMetadata()).toMatchObject({
      grant_types_supported: ['authorization_code', 'refresh_token', TOKEN_EXCHANGE_GRANT],
      authorization_details_types_supported: ['window'],
    });
  });

  it('issues a narrower, shorter token for another resource only when the host has approved the detail', async () => {
    const { h, approvals, seen, nowS } = host();
    const { tokens } = await connect(h, { scope: 'people:read people:write' });

    const refused = await exchange(h, form(tokens.access_token));
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe('invalid_authorization_details');

    approvals.set('w1', { until: nowS() + 600, sub: seen[0].credential.identity.sub, clientId: CLAUDE_ID });
    const ok = await exchange(h, form(tokens.access_token, { scope: 'people:read' }));
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({
      issued_token_type: ACCESS_TOKEN_TYPE,
      token_type: 'Bearer',
      scope: 'people:read',
      authorization_details: [{ type: 'window', id: 'w1' }],
    });
    expect(ok.body.refresh_token).toBeUndefined();
    expect(ok.body.expires_in as number).toBeLessThanOrEqual(600);
    expect(ok.body.expires_in as number).toBeGreaterThan(590);

    const token = ok.body.access_token as string;
    const auth = await h.agents.authenticate(bearer(token, '/v1'), API);
    expect(auth.ok).toBe(true);
    if (!auth.ok) return;
    expect(auth.credential.resource).toBe(API);
    expect(auth.credential.scopes).toEqual(['people:read']);
    expect(auth.credential.authorizationDetails).toEqual([{ type: 'window', id: 'w1' }]);
    // Bound to its resource, like every Agent Credential.
    expect((await h.agents.authenticate(bearer(token), MCP)).ok).toBe(false);
    // The Agent's own credential carries no details.
    const own = await h.agents.authenticate(bearer(tokens.access_token), MCP);
    expect(own.ok && own.credential.authorizationDetails).toBe(undefined);
  });

  it('never outlives the access token lifetime, the approval, or the Connection', async () => {
    const { h, approvals, nowS } = host();
    const { tokens } = await connect(h);
    const sub = (await h.agents.authenticate(bearer(tokens.access_token), MCP)) as { ok: true; credential: AgentCredential };
    approvals.set('w1', { until: nowS() + 10 * 3600, sub: sub.credential.identity.sub, clientId: CLAUDE_ID });
    expect((await exchange(h, form(tokens.access_token))).body.expires_in).toBe(3600);
    approvals.set('w1', { until: nowS() - 1, sub: sub.credential.identity.sub, clientId: CLAUDE_ID });
    expect((await exchange(h, form(tokens.access_token))).body.error).toBe('invalid_authorization_details');
  });

  it('checks the approval again on every request, so ending it in the host ends the token', async () => {
    const { h, approvals, nowS } = host();
    const { tokens } = await connect(h);
    const sub = ((await h.agents.authenticate(bearer(tokens.access_token), MCP)) as { ok: true; credential: AgentCredential }).credential.identity.sub;
    approvals.set('w1', { until: nowS() + 600, sub, clientId: CLAUDE_ID });
    const token = (await exchange(h, form(tokens.access_token))).body.access_token as string;
    expect((await h.agents.authenticate(bearer(token, '/v1'), API)).ok).toBe(true);
    approvals.delete('w1');
    const after = await h.agents.authenticate(bearer(token, '/v1'), API);
    expect(after.ok).toBe(false);
    expect(!after.ok && after.description).toMatch(/approval/);

    // Ending the Connection ends it too.
    approvals.set('w1', { until: nowS() + 600, sub, clientId: CLAUDE_ID });
    const again = (await exchange(h, form(tokens.access_token))).body.access_token as string;
    const [conn] = await h.agents.listConnections(sub);
    await h.agents.revokeConnection(conn.id);
    expect((await h.agents.authenticate(bearer(again, '/v1'), API)).ok).toBe(false);
  });

  it('expires with the approval even inside the access token lifetime', async () => {
    const { h, approvals, nowS } = host();
    const { tokens } = await connect(h);
    const sub = ((await h.agents.authenticate(bearer(tokens.access_token), MCP)) as { ok: true; credential: AgentCredential }).credential.identity.sub;
    approvals.set('w1', { until: nowS() + 60, sub, clientId: CLAUDE_ID });
    const token = (await exchange(h, form(tokens.access_token))).body.access_token as string;
    h.tick(61);
    expect((await h.agents.authenticate(bearer(token, '/v1'), API)).ok).toBe(false);
  });

  it('refuses what it should: more scopes, unknown types, bad targets, chained exchanges, other clients', async () => {
    const { h, approvals, nowS } = host();
    const { tokens } = await connect(h, { scope: 'people:read' });
    const sub = ((await h.agents.authenticate(bearer(tokens.access_token), MCP)) as { ok: true; credential: AgentCredential }).credential.identity.sub;
    approvals.set('w1', { until: nowS() + 600, sub, clientId: CLAUDE_ID });
    const t = tokens.access_token;
    expect((await exchange(h, form(t, { scope: 'people:write' }))).body.error).toBe('invalid_scope');
    expect((await exchange(h, form(t, { authorization_details: '[{"type":"other"}]' }))).body.error).toBe('invalid_authorization_details');
    expect((await exchange(h, form(t, { authorization_details: '{"type":"window"}' }))).body.error).toBe('invalid_authorization_details');
    expect((await exchange(h, form(t, { authorization_details: JSON.stringify([{ type: 'window', pad: 'x'.repeat(3000) }]) }))).body.error).toBe('invalid_authorization_details');
    expect((await exchange(h, form(t, { resource: 'https://elsewhere.example/api' }))).body.error).toBe('invalid_target');
    expect((await exchange(h, form(t, { subject_token_type: 'urn:ietf:params:oauth:token-type:jwt' }))).body.error).toBe('invalid_request');
    expect((await exchange(h, form(t, { requested_token_type: 'urn:ietf:params:oauth:token-type:refresh_token' }))).body.error).toBe('invalid_request');
    expect((await exchange(h, form(t, { client_id: CLI_ID }))).body.error).toBe('invalid_grant');
    expect((await exchange(h, form('e9agent_forged.sig'))).body.error).toBe('invalid_grant');
    const derived = (await exchange(h, form(t))).body.access_token as string;
    expect((await exchange(h, form(derived))).body.error).toBe('invalid_grant');
    // The library form works without HTTP, with the same checks.
    expect((await h.agents.exchangeToken({ subjectToken: t, resource: API, authorizationDetails: [{ type: 'window', id: 'w1' }] })).ok).toBe(true);
    expect((await h.agents.exchangeToken({ subjectToken: derived, resource: API, authorizationDetails: [{ type: 'window', id: 'w1' }] })).ok).toBe(false);
  });

  it('revoking an exchanged token ends the host approval, not the Connection', async () => {
    const { h, approvals, revoked, nowS } = host();
    const { tokens } = await connect(h);
    const sub = ((await h.agents.authenticate(bearer(tokens.access_token), MCP)) as { ok: true; credential: AgentCredential }).credential.identity.sub;
    approvals.set('w1', { until: nowS() + 600, sub, clientId: CLAUDE_ID });
    const token = (await exchange(h, form(tokens.access_token))).body.access_token as string;
    expect((await h.agents.handle(post('/oauth/revoke', { token })))?.status).toBe(200);
    expect(revoked).toEqual(['w1']);
    expect((await h.agents.authenticate(bearer(token, '/v1'), API)).ok).toBe(false);
    expect((await h.agents.authenticate(bearer(tokens.access_token), MCP)).ok).toBe(true);
    expect(new URL(ISSUER).origin).toBe(ISSUER);
  });
});
