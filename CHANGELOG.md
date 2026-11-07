# Changelog

## 1.1.0

Connecting from a phone no longer fails with "opened in a different browser, or it took too long".

- **Several attempts per browser.** The `e9_agent_flow` cookie holds up to five flows, so tapping Connect
  twice no longer breaks the first tab.
- **Sign-in returning to another browser** (a link opened in another app) now offers **Continue in this
  browser**: a new flow bound to that browser (`GET /oauth/resume`), a fresh Delegate sign-in, and always the
  consent screen with a warning. Nothing is finished without the person choosing to.
- **Separate messages** for an expired attempt and an approval page from another browser.
- **Consent page buttons** have an explicit text colour and `color-scheme: light`, so Cancel is visible
  in dark mode on iOS.
- README: "Connecting Claude", including `identity.fields.email`.
- `npm run build` runs on install from git (`prepare`), so hosts can depend on `github:engine9-ai/core-agent-credentials`.

| What a site changes | |
| --- | --- |
| Nothing | Hosts that route `/oauth/*` to `handle()` get `/oauth/resume` automatically |

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
