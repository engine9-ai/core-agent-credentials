import { authorizeUrl } from '@engine9/id';
import type { Identity } from '@engine9/id';
import {
  DYNAMIC_CLIENT_PREFIX,
  createClientResolver,
  redirectUriMatches,
  redirectUriProblem,
} from './clients';
import type { ResolvedClient } from './clients';
import { randomToken, safeEqual, sha256Base64Url } from './crypto';
import { createIdentityVerifier } from './delegate';
import {
  CORS_HEADERS,
  cookie,
  html,
  json,
  oauthError,
  preflight,
  readCookie,
  readForm,
  readJsonObject,
  redirect,
} from './http';
import { consentPage, errorPage } from './pages';
import {
  hashRefreshToken,
  isAccessToken,
  isRefreshToken,
  newRefreshToken,
  readAccessToken,
  signAccessToken,
} from './tokens';
import type {
  AgentCredentialEvent,
  AgentCredentialsOptions,
  AgentIdentity,
  AuthenticateResult,
  Connection,
} from './types';

export const DEFAULT_DELEGATE_URL = 'https://delegate.network';
const FLOW_COOKIE = 'e9_agent_flow';
const FLOW_TTL_SECONDS = 15 * 60;
const CODE_TTL_SECONDS = 60;
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
const PKCE_CHALLENGE = /^[A-Za-z0-9_-]{43,128}$/;
const PKCE_VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;

export interface AgentCredentials {
  /** Answers this library's routes. Null for any other request, so the host can carry on. */
  handle(request: Request): Promise<Response | null>;
  /** Checks the Agent Credential on a request for `resource` (required when there are several). */
  authenticate(request: Request, resource?: string): Promise<AuthenticateResult>;
  /** A 401 that tells an Agent where to sign in. */
  unauthorized(resource?: string, detail?: { error?: string; description?: string; scope?: string[] }): Response;
  /** A 403 for a credential that lacks a scope the host requires. */
  insufficientScope(scope: string[], resource?: string): Response;
  authorizationServerMetadata(): Record<string, unknown>;
  protectedResourceMetadata(resource?: string): Record<string, unknown>;
  /** URL of the protected-resource metadata for `resource` (RFC 9728). */
  protectedResourceMetadataUrl(resource?: string): string;
  /** A person's active Connections, newest first. */
  listConnections(sub: string): Promise<Connection[]>;
  /** Ends a Connection and every credential issued for it. With `sub`, only that person's. */
  revokeConnection(id: string, options?: { sub?: string }): Promise<boolean>;
  /** Deletes expired rows. Run it on a schedule. */
  prune(): Promise<void>;
}

interface FlowData {
  client_id: string;
  redirect_uri: string;
  state: string | null;
  code_challenge: string;
  scopes: string[];
  resource: string;
  nonce: string;
  identity?: AgentIdentity;
}

interface CodeData {
  connection_id: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  scopes: string[];
  resource: string;
}

function isLoopbackHttp(url: URL): boolean {
  return url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
}

function normalizeResource(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.hash || (url.protocol !== 'https:' && !isLoopbackHttp(url))) return null;
    return url.href;
  } catch {
    return null;
  }
}

function withParams(uri: string, params: Record<string, string | null | undefined>): string {
  const url = new URL(uri);
  for (const [key, value] of Object.entries(params)) {
    if (value !== null && value !== undefined && value !== '') url.searchParams.set(key, value);
  }
  return url.toString();
}

function identitySnapshot(identity: Identity): AgentIdentity {
  return {
    sub: identity.sub,
    ...(identity.merged_from ? { merged_from: identity.merged_from } : {}),
    level: identity.level,
    ...(identity.fields ? { fields: identity.fields } : {}),
    ...(identity.auth ? { auth: identity.auth } : {}),
  };
}

/** The Agent's registration can change mid-flow (a metadata document is re-fetched). */
function stillRegistered(client: ResolvedClient, redirectUri: string): boolean {
  return client.redirect_uris.some((r) => redirectUriMatches(r, redirectUri));
}

function isActive(connection: Connection | null, now: number): connection is Connection {
  return Boolean(connection && connection.revoked_at === null && connection.expires_at > now);
}

export function createAgentCredentials(options: AgentCredentialsOptions): AgentCredentials {
  const issuerUrl = new URL(options.issuer);
  if (issuerUrl.protocol !== 'https:' && !isLoopbackHttp(issuerUrl)) {
    throw new Error('issuer must be https (http only on localhost)');
  }
  if (issuerUrl.pathname !== '/' || issuerUrl.search || issuerUrl.hash) {
    throw new Error('issuer must be an origin, with no path');
  }
  const issuer = issuerUrl.origin;
  const domain = issuerUrl.host;
  const secure = issuerUrl.protocol === 'https:';

  const resources = options.resources.map((r) => {
    const normalized = normalizeResource(r);
    if (!normalized) throw new Error(`resource ${r} must be an https URL with no fragment`);
    return normalized;
  });
  if (resources.length === 0) throw new Error('resources must list at least one resource');

  const secrets = Array.isArray(options.secret) ? options.secret : [options.secret];
  if (secrets.length === 0 || secrets.some((s) => typeof s !== 'string' || s.length < 32)) {
    throw new Error('secret must be at least 32 characters');
  }

  const scopeWords = options.scopes;
  const scopeNames = Object.keys(scopeWords);
  if (scopeNames.length === 0) throw new Error('scopes must list at least one scope');
  for (const name of scopeNames) {
    if (!SCOPE_TOKEN.test(name)) throw new Error(`scope ${JSON.stringify(name)} is not a valid OAuth scope`);
  }
  const defaultScopes = options.defaultScopes ?? scopeNames;
  for (const name of defaultScopes) {
    if (!(name in scopeWords)) throw new Error(`defaultScopes names unknown scope ${name}`);
  }

  const basePath = (options.basePath ?? '/oauth').replace(/\/+$/, '');
  if (!basePath.startsWith('/')) throw new Error('basePath must start with /');

  const accessTtl = options.accessTokenTtlSeconds ?? 3600;
  const refreshTtl = options.refreshTokenTtlSeconds ?? 30 * 24 * 3600;
  const maxAge = options.connectionMaxAgeSeconds ?? 90 * 24 * 3600;
  const delegateUrl = (options.delegate?.url ?? DEFAULT_DELEGATE_URL).replace(/\/+$/, '');
  const minLevel = options.delegate?.minLevel ?? 3;
  const store = options.store;
  const fetchImpl = options.fetch ?? ((input, init) => fetch(input, init));
  const nowMs = options.now ?? (() => Date.now());
  const now = () => Math.floor(nowMs() / 1000);
  const dynamic = options.registration?.dynamic ?? false;
  const metadataDocuments = options.registration?.metadataDocuments ?? true;

  for (const client of options.registration?.clients ?? []) {
    if (client.client_id.startsWith(DYNAMIC_CLIENT_PREFIX) || client.client_id.startsWith('https:')) {
      throw new Error(`pre-registered client_id ${client.client_id} must not look like a dynamic or metadata client_id`);
    }
    for (const uri of client.redirect_uris) {
      const problem = redirectUriProblem(uri);
      if (problem) throw new Error(`client ${client.client_id} redirect_uri ${uri} ${problem}`);
    }
  }

  const resolver = createClientResolver({
    clients: options.registration?.clients ?? [],
    metadataDocuments,
    dynamic,
    store,
    fetchImpl,
    now: nowMs,
  });
  const verifyIdentity = createIdentityVerifier({
    delegateUrl,
    domain,
    jwks: options.delegate?.jwks,
    fetchImpl,
  });

  const endpoint = (name: string) => `${issuer}${basePath}/${name}`;
  const flowCookie = (value: string, age = FLOW_TTL_SECONDS) =>
    cookie(FLOW_COOKIE, value, { path: basePath, maxAge: age, secure });
  const clearFlowCookie = () => flowCookie('', 0);

  async function emit(event: AgentCredentialEvent): Promise<void> {
    if (!options.onEvent) return;
    try {
      await options.onEvent(event);
    } catch (error) {
      console.error('core-agent-credentials onEvent failed', error);
    }
  }

  function targetResource(resource?: string): string {
    if (resource === undefined) {
      if (resources.length === 1) return resources[0];
      throw new Error('resource is required when more than one resource is configured');
    }
    const normalized = normalizeResource(resource);
    if (!normalized || !resources.includes(normalized)) throw new Error(`${resource} is not a configured resource`);
    return normalized;
  }

  function protectedResourceMetadataUrl(resource?: string): string {
    const url = new URL(targetResource(resource));
    const path = url.pathname === '/' ? '' : url.pathname;
    return `${url.origin}/.well-known/oauth-protected-resource${path}`;
  }

  function authenticateHeader(resource: string, parts: Record<string, string | undefined>): string {
    const params = [`resource_metadata="${protectedResourceMetadataUrl(resource)}"`];
    for (const [key, value] of Object.entries(parts)) {
      if (value) params.push(`${key}="${value.replace(/["\\]/g, '')}"`);
    }
    return `Bearer ${params.join(', ')}`;
  }

  function unauthorized(
    resource?: string,
    detail: { error?: string; description?: string; scope?: string[] } = {},
  ): Response {
    const target = targetResource(resource);
    return json({ error: detail.error ?? 'unauthorized', error_description: detail.description }, 401, {
      ...CORS_HEADERS,
      'Access-Control-Expose-Headers': 'WWW-Authenticate',
      'WWW-Authenticate': authenticateHeader(target, {
        error: detail.error,
        error_description: detail.description,
        scope: detail.scope?.join(' '),
      }),
    });
  }

  function insufficientScope(scope: string[], resource?: string): Response {
    const target = targetResource(resource);
    return json({ error: 'insufficient_scope', scope: scope.join(' ') }, 403, {
      ...CORS_HEADERS,
      'Access-Control-Expose-Headers': 'WWW-Authenticate',
      'WWW-Authenticate': authenticateHeader(target, { error: 'insufficient_scope', scope: scope.join(' ') }),
    });
  }

  function authorizationServerMetadata(): Record<string, unknown> {
    return {
      issuer,
      authorization_endpoint: endpoint('authorize'),
      token_endpoint: endpoint('token'),
      revocation_endpoint: endpoint('revoke'),
      ...(dynamic ? { registration_endpoint: endpoint('register') } : {}),
      scopes_supported: scopeNames,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
      revocation_endpoint_auth_methods_supported: ['none'],
      client_id_metadata_document_supported: metadataDocuments,
      authorization_response_iss_parameter_supported: true,
    };
  }

  function protectedResourceMetadata(resource?: string): Record<string, unknown> {
    return {
      resource: targetResource(resource),
      authorization_servers: [issuer],
      scopes_supported: scopeNames,
      bearer_methods_supported: ['header'],
    };
  }

  function problemPage(title: string, message: string, cookies: string[] = []): Response {
    return html(errorPage(title, message), 400, cookies);
  }

  /** Errors after the client and redirect URI are known go back to the Agent (RFC 6749 4.1.2.1). */
  function backToAgent(
    flow: Pick<FlowData, 'redirect_uri' | 'state'>,
    error: string,
    description: string,
    cookies: string[] = [],
  ): Response {
    return redirect(
      withParams(flow.redirect_uri, { error, error_description: description, state: flow.state, iss: issuer }),
      cookies,
    );
  }

  function personLabel(identity: AgentIdentity): string {
    return identity.fields?.email ?? identity.fields?.display_name ?? `your ${domain} account`;
  }

  async function issueCode(connection: Connection, flow: FlowData, scopes: string[]): Promise<Response> {
    const code = randomToken(32);
    const data: CodeData = {
      connection_id: connection.id,
      client_id: flow.client_id,
      redirect_uri: flow.redirect_uri,
      code_challenge: flow.code_challenge,
      scopes,
      resource: flow.resource,
    };
    await store.putPending({ id: code, kind: 'code', data: { ...data }, expires_at: now() + CODE_TTL_SECONDS }, now());
    return redirect(withParams(flow.redirect_uri, { code, state: flow.state, iss: issuer }), [clearFlowCookie()]);
  }

  async function authorize(url: URL): Promise<Response> {
    const q = url.searchParams;
    const clientId = q.get('client_id');
    if (!clientId) return problemPage('This agent cannot connect', 'The request did not say which agent is asking.');
    const resolved = await resolver.resolve(clientId);
    if ('problem' in resolved) {
      return problemPage('This agent cannot connect', `${domain} does not accept the agent ${clientId}: ${resolved.problem}.`);
    }
    const client = resolved.client;
    const redirectUri = q.get('redirect_uri');
    // Never redirect to a URI the Agent did not register. This is the check that
    // keeps an authorization code from being sent to whoever wrote the link.
    if (!redirectUri || !client.redirect_uris.some((r) => redirectUriMatches(r, redirectUri))) {
      return problemPage(
        'This agent cannot connect',
        `The agent asked ${domain} to send you somewhere it did not register, so ${domain} stopped here.`,
      );
    }
    const flow = { redirect_uri: redirectUri, state: q.get('state') };
    if (q.get('response_type') !== 'code') {
      return backToAgent(flow, 'unsupported_response_type', 'Only response_type=code is supported');
    }
    const challenge = q.get('code_challenge');
    if (q.get('code_challenge_method') !== 'S256' || !challenge || !PKCE_CHALLENGE.test(challenge)) {
      return backToAgent(flow, 'invalid_request', 'PKCE with code_challenge_method=S256 is required');
    }
    const requestedResources = q.getAll('resource');
    let resource: string | null = null;
    if (requestedResources.length === 0 && resources.length === 1) {
      resource = resources[0];
    } else if (requestedResources.length === 1) {
      const normalized = normalizeResource(requestedResources[0]);
      resource = normalized && resources.includes(normalized) ? normalized : null;
    }
    if (!resource) return backToAgent(flow, 'invalid_target', 'resource must name one resource on this Domain');

    const scopeParam = (q.get('scope') ?? '').split(' ').filter(Boolean);
    const scopes = scopeParam.length === 0 ? defaultScopes : [...new Set(scopeParam.filter((s) => s in scopeWords))];
    if (scopes.length === 0) return backToAgent(flow, 'invalid_scope', 'None of the requested scopes exist here');

    const id = randomToken(32);
    const data: FlowData = {
      client_id: client.client_id,
      redirect_uri: redirectUri,
      state: flow.state,
      code_challenge: challenge,
      scopes,
      resource,
      nonce: randomToken(16),
    };
    await store.putPending({ id, kind: 'authorize', data: { ...data }, expires_at: now() + FLOW_TTL_SECONDS }, now());
    const signIn = authorizeUrl({
      delegateUrl,
      domain,
      returnTo: endpoint('callback'),
      minLevel,
      fields: options.delegate?.fields ?? ['email'],
      optionalFields: options.delegate?.optionalFields,
      loginLevel: options.delegate?.loginLevel,
      loginProviders: options.delegate?.loginProviders,
      brand: options.delegate?.brand,
      nonce: data.nonce,
      state: id,
      responseMode: 'query',
    });
    return redirect(signIn, [flowCookie(id)]);
  }

  const restartMessage =
    'This step was opened in a different browser, or it took too long. Go back to the agent and connect again.';

  async function callback(request: Request, url: URL): Promise<Response> {
    const state = url.searchParams.get('state');
    const bound = readCookie(request, FLOW_COOKIE);
    if (!state || !bound || !safeEqual(state, bound)) {
      return problemPage('Sign-in cannot continue', restartMessage, [clearFlowCookie()]);
    }
    const pending = await store.takePending(state, 'authorize', now());
    if (!pending) return problemPage('Sign-in cannot continue', restartMessage, [clearFlowCookie()]);
    const flow = pending.data as unknown as FlowData;
    const clear = [clearFlowCookie()];

    const delegateError = url.searchParams.get('error');
    if (delegateError) return backToAgent(flow, 'access_denied', `Sign-in did not finish (${delegateError})`, clear);
    const token = url.searchParams.get('delegate_token');
    if (!token) return backToAgent(flow, 'access_denied', 'Sign-in returned no Identity Token', clear);
    let identity: Identity;
    try {
      identity = await verifyIdentity(token, flow.nonce);
    } catch {
      return backToAgent(flow, 'access_denied', 'The Identity Token could not be verified', clear);
    }
    if (identity.level < minLevel) {
      return backToAgent(
        flow,
        'access_denied',
        `Identity Level ${identity.level} is below the ${minLevel} this Domain requires`,
        clear,
      );
    }
    const snapshot = identitySnapshot(identity);
    const resolved = await resolver.resolve(flow.client_id);
    if ('problem' in resolved || !stillRegistered(resolved.client, flow.redirect_uri)) {
      return problemPage('This agent cannot connect', `The agent ${flow.client_id} changed its registration. Connect it again.`, clear);
    }
    const client = resolved.client;

    const existing = await store.findConnection(snapshot.sub, client.client_id, flow.resource, now());
    if (
      existing &&
      redirectUriMatches(existing.redirect_uri, flow.redirect_uri) &&
      flow.scopes.every((s) => existing.scopes.includes(s))
    ) {
      const connection: Connection = {
        ...existing,
        identity: snapshot,
        client_name: client.client_name,
        updated_at: now(),
        expires_at: now() + maxAge,
      };
      await store.saveConnection(connection);
      await emit({
        type: 'connection.updated',
        connectionId: connection.id,
        sub: connection.sub,
        clientId: connection.client_id,
        scopes: connection.scopes,
        at: now(),
      });
      return issueCode(connection, flow, flow.scopes);
    }

    const flowId = randomToken(32);
    await store.putPending(
      { id: flowId, kind: 'consent', data: { ...flow, identity: snapshot }, expires_at: now() + FLOW_TTL_SECONDS },
      now(),
    );
    const page = consentPage({
      domain,
      client,
      redirectUri: flow.redirect_uri,
      person: personLabel(snapshot),
      scopes: flow.scopes.map((name) => ({
        name,
        description: scopeWords[name],
        isNew: Boolean(existing && !existing.scopes.includes(name)),
      })),
      flowId,
      action: endpoint('consent'),
      maxAgeDays: Math.round(maxAge / 86400),
    });
    return html(page, 200, [flowCookie(flowId)]);
  }

  async function consent(request: Request): Promise<Response> {
    const form = await readForm(request);
    const flowId = form?.get('flow');
    const bound = readCookie(request, FLOW_COOKIE);
    if (!form || !flowId || !bound || !safeEqual(flowId, bound)) {
      return problemPage('This approval cannot continue', restartMessage, [clearFlowCookie()]);
    }
    const pending = await store.takePending(flowId, 'consent', now());
    if (!pending) return problemPage('This approval cannot continue', restartMessage, [clearFlowCookie()]);
    const flow = pending.data as unknown as FlowData;
    const clear = [clearFlowCookie()];
    if (form.get('decision') !== 'allow' || !flow.identity) {
      return backToAgent(flow, 'access_denied', 'The person did not allow this agent', clear);
    }
    const approved = [...new Set(form.getAll('scope'))].filter((s) => flow.scopes.includes(s));
    if (approved.length === 0) return backToAgent(flow, 'access_denied', 'The person approved no scopes', clear);
    const resolved = await resolver.resolve(flow.client_id);
    if ('problem' in resolved || !stillRegistered(resolved.client, flow.redirect_uri)) {
      return problemPage('This agent cannot connect', `The agent ${flow.client_id} changed its registration. Connect it again.`, clear);
    }

    const identity = flow.identity;
    const existing = await store.findConnection(identity.sub, flow.client_id, flow.resource, now());
    const at = now();
    const connection: Connection = existing
      ? {
          ...existing,
          scopes: approved,
          identity,
          redirect_uri: flow.redirect_uri,
          client_name: resolved.client.client_name,
          updated_at: at,
          expires_at: at + maxAge,
        }
      : {
          id: randomToken(16),
          sub: identity.sub,
          client_id: flow.client_id,
          client_name: resolved.client.client_name,
          redirect_uri: flow.redirect_uri,
          resource: flow.resource,
          scopes: approved,
          identity,
          created_at: at,
          updated_at: at,
          expires_at: at + maxAge,
          revoked_at: null,
        };
    await store.saveConnection(connection);
    await emit({
      type: existing ? 'connection.updated' : 'connection.created',
      connectionId: connection.id,
      sub: connection.sub,
      clientId: connection.client_id,
      scopes: connection.scopes,
      at,
    });
    return issueCode(connection, flow, approved);
  }

  async function issueTokens(connection: Connection, scopes: string[]): Promise<Response> {
    const granted = scopes.filter((s) => connection.scopes.includes(s) && s in scopeWords);
    if (granted.length === 0) return oauthError('invalid_scope', 'No approved scope is still available');
    const at = now();
    const exp = Math.min(at + accessTtl, connection.expires_at);
    const accessToken = await signAccessToken(
      {
        cid: connection.id,
        client_id: connection.client_id,
        client_name: connection.client_name,
        resource: connection.resource,
        scope: granted.join(' '),
        identity: connection.identity,
        connected_at: connection.updated_at,
        iat: at,
        exp,
      },
      secrets[0],
    );
    const refreshToken = newRefreshToken();
    await store.putRefresh({
      token_hash: await hashRefreshToken(refreshToken),
      connection_id: connection.id,
      client_id: connection.client_id,
      scopes: granted,
      expires_at: Math.min(at + refreshTtl, connection.expires_at),
      used_at: null,
    });
    return json(
      {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: exp - at,
        refresh_token: refreshToken,
        scope: granted.join(' '),
      },
      200,
      CORS_HEADERS,
    );
  }

  async function revokeForReuse(connectionId: string): Promise<void> {
    const connection = await store.getConnection(connectionId);
    if (connection && (await store.revokeConnection(connectionId, now()))) {
      await emit({
        type: 'connection.revoked',
        connectionId,
        sub: connection.sub,
        clientId: connection.client_id,
        reason: 'refresh_reused',
        at: now(),
      });
    }
  }

  async function token(request: Request): Promise<Response> {
    const form = await readForm(request);
    if (!form) return oauthError('invalid_request', 'Send an application/x-www-form-urlencoded body');
    const grantType = form.get('grant_type');
    const clientId = form.get('client_id');
    const resourceParam = form.get('resource');

    if (grantType === 'authorization_code') {
      const code = form.get('code');
      const verifier = form.get('code_verifier');
      if (!code || !clientId || !verifier) {
        return oauthError('invalid_request', 'code, client_id, and code_verifier are required');
      }
      // Taken before any other check: a wrong verifier still uses up the code.
      const pending = await store.takePending(code, 'code', now());
      if (!pending) return oauthError('invalid_grant', 'Unknown, expired, or used code');
      const data = pending.data as unknown as CodeData;
      if (clientId !== data.client_id) return oauthError('invalid_grant', 'The code was issued to another client');
      const redirectUri = form.get('redirect_uri');
      if (redirectUri !== null && redirectUri !== data.redirect_uri) {
        return oauthError('invalid_grant', 'redirect_uri does not match');
      }
      if (!PKCE_VERIFIER.test(verifier) || !safeEqual(await sha256Base64Url(verifier), data.code_challenge)) {
        return oauthError('invalid_grant', 'PKCE verification failed');
      }
      if (resourceParam !== null && normalizeResource(resourceParam) !== data.resource) {
        return oauthError('invalid_target', 'resource does not match the authorization');
      }
      const connection = await store.getConnection(data.connection_id);
      if (!isActive(connection, now())) return oauthError('invalid_grant', 'The connection has ended');
      return issueTokens(connection, data.scopes);
    }

    if (grantType === 'refresh_token') {
      const refreshToken = form.get('refresh_token');
      if (!refreshToken || !isRefreshToken(refreshToken)) return oauthError('invalid_request', 'refresh_token is required');
      const hash = await hashRefreshToken(refreshToken);
      const record = await store.getRefresh(hash);
      if (!record) return oauthError('invalid_grant', 'Unknown refresh token');
      if (clientId !== null && clientId !== record.client_id) {
        return oauthError('invalid_grant', 'The refresh token was issued to another client');
      }
      // A used refresh token means two parties hold it. End the Connection (OAuth 2.1 section 4.3.1).
      if (record.used_at !== null || !(await store.markRefreshUsed(hash, now()))) {
        await revokeForReuse(record.connection_id);
        return oauthError('invalid_grant', 'The refresh token was already used; the connection has ended');
      }
      if (record.expires_at <= now()) return oauthError('invalid_grant', 'The refresh token has expired');
      const connection = await store.getConnection(record.connection_id);
      if (!isActive(connection, now())) return oauthError('invalid_grant', 'The connection has ended');
      if (resourceParam !== null && normalizeResource(resourceParam) !== connection.resource) {
        return oauthError('invalid_target', 'resource does not match the connection');
      }
      const scopeParam = form.get('scope');
      let scopes = record.scopes;
      if (scopeParam) {
        const asked = scopeParam.split(' ').filter(Boolean);
        if (!asked.every((s) => record.scopes.includes(s))) {
          return oauthError('invalid_scope', 'A refresh cannot add scopes');
        }
        scopes = asked;
      }
      return issueTokens(connection, scopes);
    }

    return oauthError('unsupported_grant_type', 'Use authorization_code or refresh_token');
  }

  async function revoke(request: Request): Promise<Response> {
    const form = await readForm(request);
    const value = form?.get('token');
    const clientId = form?.get('client_id') ?? null;
    const ok = () => new Response(null, { status: 200, headers: CORS_HEADERS });
    if (!value) return ok();
    let connectionId: string | null = null;
    let ownerClient: string | null = null;
    if (isRefreshToken(value)) {
      const record = await store.getRefresh(await hashRefreshToken(value));
      connectionId = record?.connection_id ?? null;
      ownerClient = record?.client_id ?? null;
    } else if (isAccessToken(value)) {
      const payload = await readAccessToken(value, secrets);
      connectionId = payload?.cid ?? null;
      ownerClient = payload?.client_id ?? null;
    }
    if (!connectionId) return ok();
    if (clientId !== null && clientId !== ownerClient) {
      return oauthError('unauthorized_client', 'The token was issued to another client');
    }
    const connection = await store.getConnection(connectionId);
    if (connection && (await store.revokeConnection(connectionId, now()))) {
      await emit({
        type: 'connection.revoked',
        connectionId,
        sub: connection.sub,
        clientId: connection.client_id,
        reason: 'agent_revoked',
        at: now(),
      });
    }
    return ok();
  }

  async function register(request: Request): Promise<Response> {
    const body = await readJsonObject(request);
    if (!body) return oauthError('invalid_client_metadata', 'Send a JSON object');
    const uris = body.redirect_uris;
    if (!Array.isArray(uris) || uris.length === 0 || uris.length > 10 || !uris.every((u) => typeof u === 'string')) {
      return oauthError('invalid_redirect_uri', 'redirect_uris must list 1 to 10 URIs');
    }
    for (const uri of uris as string[]) {
      const problem = redirectUriProblem(uri);
      if (problem) return oauthError('invalid_redirect_uri', `${uri} ${problem}`);
    }
    const auth = body.token_endpoint_auth_method;
    if (auth !== undefined && auth !== 'none') {
      return oauthError('invalid_client_metadata', 'Only token_endpoint_auth_method none (public clients) is supported');
    }
    const grantTypes = body.grant_types;
    if (
      grantTypes !== undefined &&
      (!Array.isArray(grantTypes) || !grantTypes.every((g) => g === 'authorization_code' || g === 'refresh_token'))
    ) {
      return oauthError('invalid_client_metadata', 'grant_types may list authorization_code and refresh_token');
    }
    const responseTypes = body.response_types;
    if (responseTypes !== undefined && (!Array.isArray(responseTypes) || !responseTypes.every((r) => r === 'code'))) {
      return oauthError('invalid_client_metadata', 'response_types may list code only');
    }
    const clientName = typeof body.client_name === 'string' ? body.client_name.trim().slice(0, 100) || null : null;
    const client = {
      client_id: `${DYNAMIC_CLIENT_PREFIX}${randomToken(24)}`,
      client_name: clientName,
      redirect_uris: uris as string[],
      created_at: now(),
    };
    await store.putClient(client);
    return json(
      {
        client_id: client.client_id,
        client_id_issued_at: client.created_at,
        ...(clientName ? { client_name: clientName } : {}),
        redirect_uris: client.redirect_uris,
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
      },
      201,
      CORS_HEADERS,
    );
  }

  const localResourcePaths = new Map<string, string>();
  for (const resource of resources) {
    const url = new URL(resource);
    if (url.origin !== issuer) continue;
    localResourcePaths.set(new URL(protectedResourceMetadataUrl(resource)).pathname, resource);
  }

  async function handle(request: Request): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const method = request.method.toUpperCase();

    if (path === '/.well-known/oauth-authorization-server') {
      if (method === 'OPTIONS') return preflight();
      if (method === 'GET') return json(authorizationServerMetadata(), 200, { ...CORS_HEADERS, 'Cache-Control': 'max-age=300' });
      return null;
    }
    const prmResource = localResourcePaths.get(path);
    if (prmResource) {
      if (method === 'OPTIONS') return preflight();
      if (method === 'GET') {
        return json(protectedResourceMetadata(prmResource), 200, { ...CORS_HEADERS, 'Cache-Control': 'max-age=300' });
      }
      return null;
    }
    if (!path.startsWith(`${basePath}/`)) return null;
    const route = path.slice(basePath.length + 1);

    if (route === 'authorize' && method === 'GET') return authorize(url);
    if (route === 'callback' && method === 'GET') return callback(request, url);
    if (route === 'consent' && method === 'POST') return consent(request);
    if (route === 'token' || route === 'revoke' || (route === 'register' && dynamic)) {
      if (method === 'OPTIONS') return preflight();
      if (method !== 'POST') return oauthError('invalid_request', 'Use POST', 405);
      if (route === 'token') return token(request);
      if (route === 'revoke') return revoke(request);
      return register(request);
    }
    return null;
  }

  async function authenticate(request: Request, resource?: string): Promise<AuthenticateResult> {
    const target = targetResource(resource);
    const header = request.headers.get('Authorization');
    if (!header) return { ok: false, error: 'missing', response: unauthorized(target) };
    const match = /^Bearer\s+(\S+)\s*$/i.exec(header);
    if (!match || !isAccessToken(match[1])) {
      return { ok: false, error: 'other_credential', response: unauthorized(target) };
    }
    const invalid = (description: string): AuthenticateResult => ({
      ok: false,
      error: 'invalid_token',
      response: unauthorized(target, { error: 'invalid_token', description }),
    });
    const payload = await readAccessToken(match[1], secrets);
    if (!payload) return invalid('The agent credential is not valid');
    const at = now();
    if (payload.exp <= at) return invalid('The agent credential has expired');
    if (payload.resource !== target) return invalid('The agent credential is for another resource');
    const connection = await store.getConnection(payload.cid);
    if (!isActive(connection, at)) return invalid('The connection has ended');
    return {
      ok: true,
      credential: {
        connectionId: connection.id,
        clientId: payload.client_id,
        clientName: payload.client_name,
        resource: payload.resource,
        // A person who narrows a Connection narrows tokens already issued.
        scopes: payload.scope.split(' ').filter((s) => connection.scopes.includes(s)),
        identity: payload.identity,
        connectedAt: payload.connected_at,
        expiresAt: payload.exp,
      },
    };
  }

  return {
    handle,
    authenticate,
    unauthorized,
    insufficientScope,
    authorizationServerMetadata,
    protectedResourceMetadata,
    protectedResourceMetadataUrl,
    listConnections: (sub) => store.listConnections(sub, now()),
    async revokeConnection(id, { sub } = {}) {
      const connection = await store.getConnection(id);
      if (!connection || (sub !== undefined && connection.sub !== sub)) return false;
      const revoked = await store.revokeConnection(id, now());
      if (revoked) {
        await emit({
          type: 'connection.revoked',
          connectionId: id,
          sub: connection.sub,
          clientId: connection.client_id,
          reason: 'revoked',
          at: now(),
        });
      }
      return revoked;
    },
    prune: () => store.prune(now()),
  };
}
