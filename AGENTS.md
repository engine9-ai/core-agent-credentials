# Agent guide — core-agent-credentials

`@engine9/core-agent-credentials` is MIT licensed. See [LICENSE](LICENSE).
It is optional for a core deployment. The private `server` uses it for MCP
sign-in.

## The boundary

This library answers **who is acting, through which Agent, for which
resource, with which approved scopes**. It never decides what they may do.

- Do not add roles, `person_id`, accounts, projects, or permission checks
  here. The host maps `identity.sub` to its own person and reads roles on
  each request. This mirrors Delegate, which never mints `person_id` or
  roles.
- Do not add an endpoint that issues a credential without a person's
  approval (no `client_credentials`, no password grant). Operators and
  automation use the host's API keys.
- The consent screen stays neutral: no `brand_*`. Branding goes to Delegate's
  sign-in through `delegate.brand`, as any Domain sends it.

## Vocabulary

- **Agent**: the client software. The wire keeps `client_id`.
- **Connection**: one person's remembered approval for one Agent on one
  resource. Not "Grant", which is Delegate's field-sharing decision.
- **Agent Credential**: the access token plus refresh token for a Connection.
- **Resource**: the URL a credential is bound to (RFC 8707). Not "Audience".
- Delegate terms are unchanged: **User**, **Domain**, **Identity Token**,
  **Domain UNID** (`sub`), **Identity Level**.

Never "Account", "Audience", or "Site" in APIs or docs.

## Security rules

- Never redirect to a `redirect_uri` that does not match the Agent's
  registration. Errors before that check are an HTML page, never a redirect.
- Never skip the consent screen for an Agent the person has not approved for
  these scopes and this redirect URI.
- Bind every flow to the browser that started it (the `e9_agent_flow`
  cookie), and use every pending record once.
- PKCE S256 only. Public clients only.
- No OpenID Connect discovery, no `id_token`.
- `secret` is 64 hex characters (32 random bytes) from a machine. Do not
  loosen `secretProblem` to a length check or accept a passphrase: access
  tokens can be tested offline against a guessed secret.
- Access tokens are bound to one resource. Hosts must not forward them
  upstream.

## Sources

Write code from the specs: OAuth 2.1, RFC 8414, RFC 8707, RFC 9728, RFC 7591,
RFC 7009, RFC 8252, the Client ID Metadata Document draft, and the MCP
authorization spec (2026-07-28). engine9 owns `server`, so copying from it
is allowed, but its OAuth code predates these rules; build fresh. Do not copy
from `delegate`.

Delegate's wire protocol is [`../id/docs/protocol.md`](../id/docs/protocol.md).
This library is an ordinary Domain to Delegate and needs no Delegate changes.

## Commands

```bash
npm test
npm run typecheck
npm run build
```

Tests need Node 22.5+ (`node:sqlite`). The package runs on Node 20+ and
Cloudflare Workers.

Do not git commit unless the user asks.
