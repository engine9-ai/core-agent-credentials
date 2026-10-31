import type {
  AgentCredentialStore,
  Connection,
  PendingRecord,
  RefreshRecord,
  RegisteredClient,
} from '../types';

const clone = <T>(value: T): T => structuredClone(value);

/** One process only. For tests and local development. */
export function memoryStore(): AgentCredentialStore {
  const pending = new Map<string, PendingRecord>();
  const connections = new Map<string, Connection>();
  const refresh = new Map<string, RefreshRecord>();
  const clients = new Map<string, RegisteredClient>();

  const prunePending = (now: number) => {
    for (const [id, record] of pending) if (record.expires_at <= now) pending.delete(id);
  };

  return {
    async putPending(record, now) {
      prunePending(now);
      pending.set(record.id, clone(record));
    },
    async takePending(id, kind, now) {
      const record = pending.get(id);
      if (!record) return null;
      pending.delete(id);
      return record.kind === kind && record.expires_at > now ? record : null;
    },
    async findConnection(sub, clientId, resource, now) {
      let found: Connection | null = null;
      for (const c of connections.values()) {
        if (c.sub !== sub || c.client_id !== clientId || c.resource !== resource) continue;
        if (c.revoked_at !== null || c.expires_at <= now) continue;
        if (!found || c.updated_at > found.updated_at) found = c;
      }
      return found ? clone(found) : null;
    },
    async getConnection(id) {
      const c = connections.get(id);
      return c ? clone(c) : null;
    },
    async saveConnection(connection) {
      connections.set(connection.id, clone(connection));
    },
    async listConnections(sub, now) {
      return [...connections.values()]
        .filter((c) => c.sub === sub && c.revoked_at === null && c.expires_at > now)
        .sort((a, b) => b.updated_at - a.updated_at)
        .map(clone);
    },
    async revokeConnection(id, at) {
      const c = connections.get(id);
      if (!c || c.revoked_at !== null) return false;
      c.revoked_at = at;
      return true;
    },
    async putRefresh(record) {
      refresh.set(record.token_hash, clone(record));
    },
    async getRefresh(tokenHash) {
      const r = refresh.get(tokenHash);
      return r ? clone(r) : null;
    },
    async markRefreshUsed(tokenHash, at) {
      const r = refresh.get(tokenHash);
      if (!r || r.used_at !== null) return false;
      r.used_at = at;
      return true;
    },
    async putClient(client) {
      clients.set(client.client_id, clone(client));
    },
    async getClient(clientId) {
      const c = clients.get(clientId);
      return c ? clone(c) : null;
    },
    async prune(now) {
      prunePending(now);
      for (const [hash, r] of refresh) if (r.expires_at <= now) refresh.delete(hash);
      for (const [id, c] of connections) if (c.expires_at <= now) connections.delete(id);
    },
  };
}
