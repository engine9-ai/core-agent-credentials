import type { IdentityAuth, IdentityFields, Jwks, LoginProviders, SignInBrand } from '@engine9/id';

export type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

/** An Agent the host lists in configuration (no metadata document, no registration). */
export interface PreRegisteredAgent {
  client_id: string;
  /** Shown on the consent screen. The host vouches for it. */
  client_name: string;
  redirect_uris: string[];
}

export interface DelegateSignInOptions {
  /** Delegate base URL. Default `https://delegate.network`. */
  url?: string;
  /** `min_level`. Default 3. A Connection never starts below it. */
  minLevel?: number;
  /** Required fields. Default `['email']`. */
  fields?: string[];
  optionalFields?: string[];
  loginLevel?: number;
  loginProviders?: LoginProviders;
  /** Sign-in branding for this Domain, sent on each request like any Domain does. */
  brand?: SignInBrand;
  /** Fixed keys instead of fetching `/.well-known/jwks.json` (tests, pinning). */
  jwks?: Jwks;
}

export interface RegistrationOptions {
  /** Agents the host lists itself. */
  clients?: PreRegisteredAgent[];
  /** Accept an https `client_id` that serves a Client ID Metadata Document. Default true. */
  metadataDocuments?: boolean;
  /** Serve `POST {basePath}/register` (RFC 7591). Deprecated in MCP 2026-07-28. Default false. */
  dynamic?: boolean;
}

export interface AgentCredentialsOptions {
  /** This Domain's origin, e.g. `https://www.example.com`. Also the OAuth `issuer`. */
  issuer: string;
  /** Resources an Agent Credential may be bound to (RFC 8707), e.g. `https://www.example.com/mcp`. */
  resources: string[];
  /** HMAC secret(s) for access tokens, at least 32 characters. The first signs; all verify. */
  secret: string | string[];
  store: AgentCredentialStore;
  /** Every scope an Agent may ask for, in plain words for the consent screen. */
  scopes: Record<string, string>;
  /** Scopes used when an Agent asks for none. Default: every scope. */
  defaultScopes?: string[];
  delegate?: DelegateSignInOptions;
  registration?: RegistrationOptions;
  /** Path prefix for the OAuth endpoints. Default `/oauth`. */
  basePath?: string;
  /** Default 3600 (1 hour). */
  accessTokenTtlSeconds?: number;
  /** Default 2592000 (30 days). Each refresh issues a new one. */
  refreshTokenTtlSeconds?: number;
  /** Longest a Connection lasts before the person signs in again. Default 7776000 (90 days). */
  connectionMaxAgeSeconds?: number;
  fetch?: FetchLike;
  /** Milliseconds since the epoch. Tests only. */
  now?: () => number;
  /** Connection lifecycle events, for the host's audit log. */
  onEvent?: (event: AgentCredentialEvent) => void | Promise<void>;
}

/** The Identity Token claims kept for a Connection. Who the person is, never what they may do. */
export interface AgentIdentity {
  /** Domain UNID. */
  sub: string;
  merged_from?: string;
  level: number;
  fields?: IdentityFields;
  auth?: IdentityAuth;
}

/** One person's remembered approval for one Agent on one resource. */
export interface Connection {
  id: string;
  sub: string;
  client_id: string;
  client_name: string | null;
  redirect_uri: string;
  resource: string;
  scopes: string[];
  identity: AgentIdentity;
  /** Unix seconds. */
  created_at: number;
  updated_at: number;
  expires_at: number;
  revoked_at: number | null;
}

export type PendingKind = 'authorize' | 'consent' | 'code';

export interface PendingRecord {
  id: string;
  kind: PendingKind;
  data: Record<string, unknown>;
  /** Unix seconds. */
  expires_at: number;
}

export interface RefreshRecord {
  /** SHA-256 hex of the refresh token. The token itself is never stored. */
  token_hash: string;
  connection_id: string;
  client_id: string;
  scopes: string[];
  expires_at: number;
  used_at: number | null;
}

export interface RegisteredClient {
  client_id: string;
  client_name: string | null;
  redirect_uris: string[];
  created_at: number;
}

export interface AgentCredentialStore {
  putPending(record: PendingRecord, now: number): Promise<void>;
  /** Read and delete in one step. Null when missing, expired, the wrong kind, or already taken. */
  takePending(id: string, kind: PendingKind, now: number): Promise<PendingRecord | null>;
  /** The newest active Connection for this person, Agent, and resource. */
  findConnection(sub: string, clientId: string, resource: string, now: number): Promise<Connection | null>;
  getConnection(id: string): Promise<Connection | null>;
  saveConnection(connection: Connection): Promise<void>;
  listConnections(sub: string, now: number): Promise<Connection[]>;
  /** True when this call revoked an active Connection. */
  revokeConnection(id: string, at: number): Promise<boolean>;
  putRefresh(record: RefreshRecord): Promise<void>;
  getRefresh(tokenHash: string): Promise<RefreshRecord | null>;
  /** True when this call marked it. False when it was already used. */
  markRefreshUsed(tokenHash: string, at: number): Promise<boolean>;
  putClient(client: RegisteredClient): Promise<void>;
  getClient(clientId: string): Promise<RegisteredClient | null>;
  /** Delete expired rows. */
  prune(now: number): Promise<void>;
}

/** What `authenticate` returns for a valid Agent Credential. */
export interface AgentCredential {
  connectionId: string;
  clientId: string;
  clientName: string | null;
  resource: string;
  /** Scopes the person approved for this Agent. The host still decides what they allow. */
  scopes: string[];
  identity: AgentIdentity;
  /** Unix seconds. When the person approved the Connection or last signed in for it. */
  connectedAt: number;
  /** Unix seconds. When this access token expires. */
  expiresAt: number;
}

export type AuthenticateResult =
  | { ok: true; credential: AgentCredential }
  | {
      ok: false;
      /**
       * `missing`: no bearer token. `other_credential`: a bearer token that is not an
       * Agent Credential (an API key, an Identity Token); the host may try its own checks.
       * `invalid_token`: an Agent Credential that is expired, revoked, forged, or for
       * another resource.
       */
      error: 'missing' | 'other_credential' | 'invalid_token';
      /** A 401 with `WWW-Authenticate` that points the Agent at sign-in. */
      response: Response;
    };

export type AgentCredentialEvent =
  | { type: 'connection.created' | 'connection.updated'; connectionId: string; sub: string; clientId: string; scopes: string[]; at: number }
  | { type: 'connection.revoked'; connectionId: string; sub: string; clientId: string; reason: 'revoked' | 'refresh_reused' | 'agent_revoked'; at: number };
