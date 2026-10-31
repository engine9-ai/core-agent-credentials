import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { authenticateNode, nodeHandler } from '../src/node';
import { ISSUER, authorizePath, bearer, connect, pkce, setup } from './helpers';

const servers: Array<{ close(): void }> = [];
afterEach(() => {
  for (const s of servers.splice(0)) s.close();
});

async function listen(h: ReturnType<typeof setup>, { parsedBody = false, emptyBody = false } = {}) {
  const handler = nodeHandler(h.agents);
  const server = createServer(async (req, res) => {
    if (parsedBody && req.method === 'POST') {
      // What express.urlencoded() leaves behind.
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      (req as typeof req & { body: unknown }).body = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString()));
    }
    if (emptyBody) {
      // What a global express.json() leaves on a form post: {} and an unread stream.
      (req as typeof req & { body: unknown }).body = {};
    }
    if (req.url === '/mcp') {
      const result = await authenticateNode(h.agents, req);
      res.statusCode = result.ok ? 200 : result.response.status;
      res.end(result.ok ? result.credential.identity.sub : '');
      return;
    }
    await handler(req, res, () => {
      res.statusCode = 404;
      res.end('host');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  servers.push(server);
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe('node adapter', () => {
  it('serves metadata, passes other routes on, and builds URLs from the issuer', async () => {
    const h = setup();
    const base = await listen(h);
    const meta = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json();
    expect(meta.issuer).toBe(ISSUER);
    const other = await fetch(`${base}/elsewhere`);
    expect(await other.text()).toBe('host');
  });

  it('reads a body a middleware already parsed', async () => {
    for (const parsedBody of [false, true]) {
      const h = setup();
      const { tokens } = await connect(h);
      const base = await listen(h, { parsedBody });
      const res = await fetch(`${base}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token }),
      });
      expect(res.status).toBe(200);
      const next = (await res.json()) as { access_token: string };
      const mcp = await fetch(`${base}/mcp`, { headers: bearer(next.access_token).headers });
      expect(mcp.status).toBe(200);
    }
  });

  it('reads the stream when a parser left an empty body behind', async () => {
    const h = setup();
    const { tokens } = await connect(h);
    const base = await listen(h, { emptyBody: true });
    const res = await fetch(`${base}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token }),
    });
    expect(res.status).toBe(200);
  });

  it('passes the redirect and the flow cookie through', async () => {
    const h = setup();
    const base = await listen(h);
    const p = await pkce();
    const res = await fetch(`${base}${authorizePath({ code_challenge: p.challenge, client_id: 'e9-cli', redirect_uri: 'http://127.0.0.1/callback' })}`, {
      redirect: 'manual',
    });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toMatch(/^https:\/\/delegate\.network\/identity\/authorize\?/);
    expect(res.headers.getSetCookie()).toHaveLength(1);
    expect(res.headers.getSetCookie()[0]).toMatch(/^e9_agent_flow=[^;]+; Path=\/oauth; Max-Age=900; HttpOnly; SameSite=Lax; Secure$/);
  });

  it('answers 401 with the metadata pointer through authenticateNode', async () => {
    const h = setup();
    const base = await listen(h);
    expect((await fetch(`${base}/mcp`)).status).toBe(401);
  });
});
