# Changelog

## 1.0.1

`secret` must be 32 random bytes as 64 hex characters. Until now any 32
characters passed, so `this is a secret this is a secret` was accepted.
Anyone who connects an Agent holds an access token signed with the secret
and can test guesses against it offline; a typed value let them mint access
for any person with any scope. `createAgentCredentials` now throws on any
other form, naming the entry (`secret[1]`) when a rotation list has a bad one.

| What a site changes | |
| --- | --- |
| `AGENT_CREDENTIALS_SECRET` | Run `npx e9core setup-keys` (and `--remote`) with an `@engine9/core` that writes it; it replaces a typed value. On your own servers, `openssl rand -hex 32` |
| Tests | A fixture such as `'s'.repeat(32)` throws. Use a 64-hex value |

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
