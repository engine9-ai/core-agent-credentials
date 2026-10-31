import type {
  AgentCredentialStore,
  Connection,
  PendingKind,
  PendingRecord,
  RefreshRecord,
  RegisteredClient,
} from '../types';

/**
 * The two calls the SQL store needs. Placeholders are `?`. Wrap any driver:
 * D1 (`d1Executor`), SQLite, MySQL, or a core `SQLWorker`.
 */
export interface SqlExecutor {
  all<T = Record<string, unknown>>(sql: string, params: unknown[]): Promise<T[]>;
  /** `changes` is the number of rows the statement inserted, updated, or deleted. */
  run(sql: string, params: unknown[]): Promise<{ changes: number }>;
}

interface D1Like {
  prepare(sql: string): {
    bind(...values: unknown[]): {
      all<T>(): Promise<{ results?: T[] }>;
      run(): Promise<{ meta?: { changes?: number } }>;
    };
  };
}

/** Executor for a Cloudflare D1 binding. */
export function d1Executor(db: D1Like): SqlExecutor {
  return {
    async all<T>(sql: string, params: unknown[]) {
      const result = await db.prepare(sql).bind(...params).all<T>();
      return result.results ?? [];
    },
    async run(sql: string, params: unknown[]) {
      const result = await db.prepare(sql).bind(...params).run();
      return { changes: result.meta?.changes ?? 0 };
    },
  };
}

/**
 * `create table` statements for the four tables. Times are unix seconds.
 * Lists of scopes are space-separated; identities and redirect URI lists are JSON.
 */
export function agentCredentialTablesSql(dialect: 'sqlite' | 'mysql'): string[] {
  const key = dialect === 'mysql' ? 'varchar(64)' : 'text';
  const name = dialect === 'mysql' ? 'varchar(512)' : 'text';
  const time = dialect === 'mysql' ? 'bigint' : 'integer';
  const body = dialect === 'mysql' ? 'mediumtext' : 'text';
  const index = (table: string, column: string) =>
    dialect === 'mysql'
      ? `create index ${table}_${column} on ${table} (${column})`
      : `create index if not exists ${table}_${column} on ${table} (${column})`;
  const table = (sql: string) => sql.replace('create table', 'create table if not exists');
  return [
    table(`create table agent_pending (id ${key} primary key, kind varchar(16) not null, data ${body} not null, expires_at ${time} not null)`),
    index('agent_pending', 'expires_at'),
    table(
      `create table agent_connection (id ${key} primary key, sub varchar(255) not null, client_id ${name} not null, client_name varchar(255), redirect_uri ${body} not null, resource ${name} not null, scopes ${body} not null, identity ${body} not null, created_at ${time} not null, updated_at ${time} not null, expires_at ${time} not null, revoked_at ${time})`,
    ),
    index('agent_connection', 'sub'),
    table(
      `create table agent_refresh (token_hash ${key} primary key, connection_id ${key} not null, client_id ${name} not null, scopes ${body} not null, expires_at ${time} not null, used_at ${time})`,
    ),
    index('agent_refresh', 'connection_id'),
    table(`create table agent_client (client_id ${key} primary key, client_name varchar(255), redirect_uris ${body} not null, created_at ${time} not null)`),
  ];
}

type Row = Record<string, unknown>;

const num = (v: unknown): number => Number(v);
const numOrNull = (v: unknown): number | null => (v === null || v === undefined ? null : Number(v));
const strOrNull = (v: unknown): string | null => (v === null || v === undefined ? null : String(v));
const split = (v: unknown): string[] => String(v ?? '').split(' ').filter(Boolean);

function toConnection(row: Row): Connection {
  return {
    id: String(row.id),
    sub: String(row.sub),
    client_id: String(row.client_id),
    client_name: strOrNull(row.client_name),
    redirect_uri: String(row.redirect_uri),
    resource: String(row.resource),
    scopes: split(row.scopes),
    identity: JSON.parse(String(row.identity)),
    created_at: num(row.created_at),
    updated_at: num(row.updated_at),
    expires_at: num(row.expires_at),
    revoked_at: numOrNull(row.revoked_at),
  };
}

/** Store on any SQL database through `executor`. Create the tables with `agentCredentialTablesSql`. */
export function sqlStore(executor: SqlExecutor): AgentCredentialStore {
  const { all, run } = executor;
  return {
    async putPending(record, now) {
      await run('delete from agent_pending where expires_at <= ?', [now]);
      await run('insert into agent_pending (id, kind, data, expires_at) values (?, ?, ?, ?)', [
        record.id,
        record.kind,
        JSON.stringify(record.data),
        record.expires_at,
      ]);
    },
    async takePending(id: string, kind: PendingKind, now: number): Promise<PendingRecord | null> {
      const rows = await all<Row>('select id, kind, data, expires_at from agent_pending where id = ?', [id]);
      const row = rows[0];
      if (!row) return null;
      // Whoever deletes the row owns it; a second caller sees 0 changes.
      const { changes } = await run('delete from agent_pending where id = ?', [id]);
      if (changes !== 1 || row.kind !== kind || num(row.expires_at) <= now) return null;
      return { id, kind, data: JSON.parse(String(row.data)), expires_at: num(row.expires_at) };
    },
    async findConnection(sub, clientId, resource, now) {
      const rows = await all<Row>(
        'select * from agent_connection where sub = ? and client_id = ? and resource = ? and revoked_at is null and expires_at > ? order by updated_at desc limit 1',
        [sub, clientId, resource, now],
      );
      return rows[0] ? toConnection(rows[0]) : null;
    },
    async getConnection(id) {
      const rows = await all<Row>('select * from agent_connection where id = ?', [id]);
      return rows[0] ? toConnection(rows[0]) : null;
    },
    async saveConnection(c) {
      const values = [
        c.sub,
        c.client_id,
        c.client_name,
        c.redirect_uri,
        c.resource,
        c.scopes.join(' '),
        JSON.stringify(c.identity),
        c.created_at,
        c.updated_at,
        c.expires_at,
        c.revoked_at,
      ];
      // Check first: MySQL reports 0 changed rows for an update that writes identical values.
      const found = await all<Row>('select id from agent_connection where id = ?', [c.id]);
      if (found.length > 0) {
        await run(
          'update agent_connection set sub = ?, client_id = ?, client_name = ?, redirect_uri = ?, resource = ?, scopes = ?, identity = ?, created_at = ?, updated_at = ?, expires_at = ?, revoked_at = ? where id = ?',
          [...values, c.id],
        );
      } else {
        await run(
          'insert into agent_connection (sub, client_id, client_name, redirect_uri, resource, scopes, identity, created_at, updated_at, expires_at, revoked_at, id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
          [...values, c.id],
        );
      }
    },
    async listConnections(sub, now) {
      const rows = await all<Row>(
        'select * from agent_connection where sub = ? and revoked_at is null and expires_at > ? order by updated_at desc',
        [sub, now],
      );
      return rows.map(toConnection);
    },
    async revokeConnection(id, at) {
      const { changes } = await run('update agent_connection set revoked_at = ? where id = ? and revoked_at is null', [at, id]);
      return changes === 1;
    },
    async putRefresh(r: RefreshRecord) {
      await run(
        'insert into agent_refresh (token_hash, connection_id, client_id, scopes, expires_at, used_at) values (?, ?, ?, ?, ?, ?)',
        [r.token_hash, r.connection_id, r.client_id, r.scopes.join(' '), r.expires_at, r.used_at],
      );
    },
    async getRefresh(tokenHash) {
      const rows = await all<Row>('select * from agent_refresh where token_hash = ?', [tokenHash]);
      const row = rows[0];
      if (!row) return null;
      return {
        token_hash: String(row.token_hash),
        connection_id: String(row.connection_id),
        client_id: String(row.client_id),
        scopes: split(row.scopes),
        expires_at: num(row.expires_at),
        used_at: numOrNull(row.used_at),
      };
    },
    async markRefreshUsed(tokenHash, at) {
      const { changes } = await run('update agent_refresh set used_at = ? where token_hash = ? and used_at is null', [
        at,
        tokenHash,
      ]);
      return changes === 1;
    },
    async putClient(c: RegisteredClient) {
      await run('insert into agent_client (client_id, client_name, redirect_uris, created_at) values (?, ?, ?, ?)', [
        c.client_id,
        c.client_name,
        JSON.stringify(c.redirect_uris),
        c.created_at,
      ]);
    },
    async getClient(clientId) {
      const rows = await all<Row>('select * from agent_client where client_id = ?', [clientId]);
      const row = rows[0];
      if (!row) return null;
      return {
        client_id: String(row.client_id),
        client_name: strOrNull(row.client_name),
        redirect_uris: JSON.parse(String(row.redirect_uris)),
        created_at: num(row.created_at),
      };
    },
    async prune(now) {
      await run('delete from agent_pending where expires_at <= ?', [now]);
      await run('delete from agent_refresh where expires_at <= ?', [now]);
      await run('delete from agent_connection where expires_at <= ?', [now]);
    },
  };
}
