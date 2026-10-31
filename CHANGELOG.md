# Changelog

## 0.1.0

First release.

- OAuth 2.1 authorization server for MCP clients: authorization code with
  PKCE S256, RFC 8414 metadata, RFC 9728 protected-resource metadata,
  RFC 8707 resource binding, RFC 7009 revocation.
- Agents identified by Client ID Metadata Document, a listed client, or
  (opt-in) Dynamic Client Registration.
- People sign in through Delegate and approve each Agent on a consent screen.
  Approvals are remembered as Connections.
- `e9agent_` access tokens (HMAC, 1 hour) and rotating `e9agentrefresh_`
  refresh tokens with reuse detection.
- `sqlStore` (D1, SQLite, MySQL through a two-call executor) and
  `memoryStore`.
- `@engine9/core-agent-credentials/node` for Express and `node:http`.

| What a site changes | |
| --- | --- |
| New secret | `AGENT_CREDENTIALS_SECRET`, 32+ random bytes |
| New tables | `agentCredentialTablesSql('sqlite' \| 'mysql')` |
| Delegate | Nothing. The issuer must already be an allowed Domain. |
