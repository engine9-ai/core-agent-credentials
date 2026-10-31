# @engine9/core-agent-credentials

OAuth 2.1 credentials for AI agents (MCP clients such as Claude, ChatGPT, and
Cursor) on an engine9 core deployment.

A person connects an agent to your Domain. They sign in through Delegate, see
which agent is asking and what it wants, and approve it. The agent gets a
short-lived access token bound to your MCP endpoint, plus a refresh token.

This library answers **who is acting, through which agent, for which
resource, with which approved scopes**. It never decides what they may do.
Your host does that on every request, the same way it does for a person's
own session. Delegate already works this way for people: it says who someone
is and never mints roles.

## How a connection works

1. The agent calls your MCP endpoint without a token. Your host answers with
   `authenticate(...).response`: a 401 whose `WWW-Authenticate` names
   `/.well-known/oauth-protected-resource/mcp` (RFC 9728).
2. The agent reads that document, then `/.well-known/oauth-authorization-server`
   (RFC 8414). Both are served by this library on your Domain.
3. The agent opens `/oauth/authorize` with PKCE S256 and `resource` (RFC 8707).
   The library identifies the agent:
   - its Client ID Metadata Document, preferred in MCP 2026-07-28;
   - a client you list in configuration;
   - or Dynamic Client Registration, if you turn it on.

   The `redirect_uri` must exactly match one the agent registered. If it
   doesn't, the person sees an error page and is never redirected.
4. The person goes to Delegate as an ordinary request from your Domain
   (`response_mode=query`, `min_level` 3 by default, your `brand_*`).
   Delegate needs nothing new for this.
5. The library verifies the Identity Token and shows a consent screen:
   - It names the agent by what can be verified. For a metadata document,
     that is the host that served it.
   - It lists the scopes in your words. The person can untick any of them.

   The approval becomes a **Connection**, remembered for that person, agent,
   and resource.
6. The agent exchanges the code for an **Agent Credential**: an access token
   (`e9agent_…`, 1 hour) and a refresh token (`e9agentrefresh_…`, rotated on
   every use).
7. Each MCP request calls `authenticate`. You get the person's Identity
   Token claims and the approved scopes, and you decide.

The consent screen is skipped next time, unless one of these happens:

- the agent asks for scopes the person has not approved;
- the agent uses a redirect URI the Connection has not seen;
- the Connection was revoked or reached its maximum age.

Redirect URIs must match exactly, so a remembered approval can only ever
send codes to that agent's own callback.

## Quick start (Cloudflare Worker)

```js
import { createAgentCredentials, d1Executor, sqlStore } from '@engine9/core-agent-credentials';

// One instance per isolate, so metadata documents and Delegate's keys stay cached.
let agents;
function agentsFor(env) {
  return (agents ??= createAgentCredentials({
    issuer: 'https://www.example.com',
    resources: ['https://www.example.com/mcp'],
    secret: env.AGENT_CREDENTIALS_SECRET, // 32+ random bytes, its own secret
    store: sqlStore(d1Executor(env.DB)),
    scopes: {
      'people:read': 'See people and their history',
      'people:write': 'Add and change people',
    },
  }));
}

export default {
  async fetch(request, env) {
    const agents = agentsFor(env);
    const handled = await agents.handle(request);
    if (handled) return handled;

    if (new URL(request.url).pathname === '/mcp') {
      const auth = await agents.authenticate(request);
      if (!auth.ok) return auth.response; // or try an API key when auth.error === 'other_credential'
      const { identity, scopes } = auth.credential;
      // Your decision: map identity.sub (Domain UNID) to a person, read their
      // roles now, and intersect with `scopes`.
      return handleMcp(request, { identity, scopes });
    }
    return env.ASSETS.fetch(request);
  },
};
```

Create the tables once:

```js
import { agentCredentialTablesSql } from '@engine9/core-agent-credentials';
console.log(agentCredentialTablesSql('sqlite').join(';\n') + ';');
// then: npx wrangler d1 execute <database> --file tables.sql
```

## Quick start (Express)

```js
import express from 'express';
import { createAgentCredentials, sqlStore } from '@engine9/core-agent-credentials';
import { authenticateNode, nodeHandler } from '@engine9/core-agent-credentials/node';

const agents = createAgentCredentials({ /* as above, store: sqlStore(yourExecutor) */ });
const app = express();
app.use(nodeHandler(agents)); // mount before routes that would claim /oauth/*

app.post('/mcp', async (req, res) => {
  const auth = await authenticateNode(agents, req);
  if (!auth.ok) {
    res.status(auth.response.status);
    auth.response.headers.forEach((v, k) => res.setHeader(k, v));
    return res.end(await auth.response.text());
  }
  // auth.credential.identity, auth.credential.scopes
});
```

`nodeHandler` builds request URLs from `issuer`, never from the `Host`
header. It also accepts a body that `express.urlencoded()` or `express.json()`
already parsed.

## What your host decides

| Question | Where it is answered |
| --- | --- |
| Who is this person? | `credential.identity.sub` (Domain UNID), plus `fields` they shared. Map it to your person the way you map an Identity Token. |
| What may they do now? | Your roles (core: `person_segment`), read on the request. Intersect with `credential.scopes`. |
| Is their sign-in recent enough? | `credential.identity.level`, `identity.auth.auth_time`, and `credential.connectedAt`. A Connection lasts up to 90 days by default. Refuse admin work on an old sign-in if your policy says so. |
| Which scope does each tool need? | Your MCP server. Answer `insufficientScope([...])` when one is missing. |
| Can they see and end their Connections? | Build a page on `listConnections(sub)` and `revokeConnection(id, { sub })`. |
| Who is allowed to register? | Rate-limit `/oauth/authorize` and `/oauth/register` at your edge. |

Removing someone's role takes effect on the agent's next request, because
you read roles on the request. Revoking a Connection ends every token issued
for it at once.

## Options

| Option | Default | Notes |
| --- | --- | --- |
| `issuer` | required | Your origin, no path. Also the Delegate Domain (`host` or `host:port`). |
| `resources` | required | The URLs tokens may be bound to. |
| `secret` | required | 32+ characters. Pass `[new, old]` to rotate: the first signs, all verify. |
| `store` | required | `sqlStore(executor)` or `memoryStore()` (tests). |
| `scopes` | required | Every scope an agent may hold, in plain words. Do not list `admin` unless you mean it. |
| `defaultScopes` | all scopes | Used when the agent asks for none. |
| `delegate` | | `url`, `minLevel` (3), `fields` (`['email']`), `optionalFields`, `loginLevel`, `loginProviders`, `brand`. |
| `registration` | | `clients` (listed agents), `metadataDocuments` (true), `dynamic` (false). |
| `basePath` | `/oauth` | |
| `accessTokenTtlSeconds` | 3600 | |
| `refreshTokenTtlSeconds` | 30 days | Never past the Connection's end. |
| `connectionMaxAgeSeconds` | 90 days | Signing in again restarts it. |
| `onEvent` | | `connection.created`, `connection.updated`, `connection.revoked`, for your audit log. |

## Endpoints

| Method | Path | |
| --- | --- | --- |
| GET | `/.well-known/oauth-authorization-server` | RFC 8414 |
| GET | `/.well-known/oauth-protected-resource/<path>` | RFC 9728, for each resource on the issuer origin. For a resource elsewhere, serve `protectedResourceMetadata(resource)` there yourself. |
| GET | `/oauth/authorize` | Authorization code + PKCE S256 |
| GET | `/oauth/callback` | Delegate returns here |
| POST | `/oauth/consent` | The consent screen posts here |
| POST | `/oauth/token` | `authorization_code`, `refresh_token` |
| POST | `/oauth/revoke` | RFC 7009. Ends the Connection. |
| POST | `/oauth/register` | RFC 7591, only with `registration.dynamic` |

There is no OpenID Connect discovery and no `id_token`.

## Agent registration

- **Client ID Metadata Documents** (on by default). The `client_id` is an
  https URL serving JSON with the same `client_id` and its `redirect_uris`.
  The document is fetched with a 5-second timeout and a 10 KB limit, cached
  for 10 minutes. Local hosts and IP addresses are refused. On Node, also
  block private networks at your egress if agents could point at them.
- **Listed clients**: `registration.clients`. Their `client_name` is shown as
  you wrote it.
- **Dynamic Client Registration** (off by default; deprecated in MCP
  2026-07-28). Turn it on for agents that still need it. Anyone can register,
  so the consent screen says the app is unverified and shows where its
  access will go.

Only public clients are supported (`token_endpoint_auth_method: none`).
Loopback redirects may use any port (RFC 8252).

## Tokens

- **Access token**: `e9agent_<payload>.<HMAC-SHA256>`. The payload carries
  the Connection id, agent, resource, scopes, the Identity Token claims, and
  `exp`. `authenticate` checks the signature, `exp`, and the resource, then
  reads the Connection, so a revoked Connection stops working immediately.
- **Refresh token**: 32 random bytes. Only its SHA-256 is stored. Each use
  issues a new one. Presenting a used one ends the Connection (OAuth 2.1
  §4.3.1), because two parties hold it.

Grep your repositories and logs for `e9agent_` the way you grep for `e9key_`.

## Storage

`sqlStore` needs two calls, `all(sql, params)` and `run(sql, params) →
{ changes }`, with `?` placeholders. `d1Executor(env.DB)` wraps D1. Wrap
SQLite, MySQL, or a core `SQLWorker` the same way.

Tables: `agent_pending`, `agent_connection`, `agent_refresh`,
`agent_client`. Times are unix seconds. Call `prune()` on a schedule to
delete expired rows.

## License

MIT. See [LICENSE](LICENSE).
