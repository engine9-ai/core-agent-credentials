import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';
import { agentCredentialTablesSql, sqlStore } from '../src/stores/sql';
import type { SqlExecutor } from '../src/stores/sql';
import { CLAUDE_ID, MCP, SUB, bearer, connect, pkce, post, returnFromDelegate, setup, start, agentRedirect, exchange } from './helpers';

const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as typeof import('node:sqlite');

function sqliteExecutor(): SqlExecutor {
  const db = new DatabaseSync(':memory:');
  for (const statement of agentCredentialTablesSql('sqlite')) db.exec(statement);
  return {
    async all<T>(sql: string, params: unknown[]) {
      return db.prepare(sql).all(...(params as never[])) as T[];
    },
    async run(sql: string, params: unknown[]) {
      return { changes: Number(db.prepare(sql).run(...(params as never[])).changes) };
    },
  };
}

describe('sqlStore on SQLite', () => {
  it('runs the whole flow, remembered consent, refresh reuse, and prune', async () => {
    const h = setup({ store: sqlStore(sqliteExecutor()) });
    const { tokens } = await connect(h);
    const ok = await h.agents.authenticate(bearer(tokens.access_token));
    expect(ok.ok).toBe(true);

    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge, scope: 'people:read' });
    const code = agentRedirect(await returnFromDelegate(h, s)).get('code')!;
    expect((await exchange(h, code, p)).res.status).toBe(200);

    const connections = await h.agents.listConnections(SUB);
    expect(connections).toHaveLength(1);
    expect(connections[0]).toMatchObject({ client_id: CLAUDE_ID, resource: MCP, scopes: ['people:read', 'people:write'] });
    expect(connections[0].identity.fields?.email).toBe('alex@example.com');

    const refresh = (t: string) => h.agents.handle(post('/oauth/token', { grant_type: 'refresh_token', refresh_token: t }));
    expect((await refresh(tokens.refresh_token))?.status).toBe(200);
    expect((await refresh(tokens.refresh_token))?.status).toBe(400);
    expect(await h.agents.listConnections(SUB)).toHaveLength(0);

    h.tick(100 * 86400);
    await h.agents.prune();
  });

  it('emits MySQL tables too', () => {
    const sql = agentCredentialTablesSql('mysql').join('\n');
    expect(sql).toContain('create table if not exists agent_connection (id varchar(64) primary key');
    expect(sql).toContain('expires_at bigint not null');
  });
});
