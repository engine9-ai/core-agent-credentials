import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AgentCredentials } from './agentCredentials';
import type { AuthenticateResult } from './types';

type NodeRequest = IncomingMessage & { body?: unknown; originalUrl?: string };
type Next = (error?: unknown) => void;

const MAX_BODY_BYTES = 16 * 1024;

async function readStream(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
    size += buf.length;
    if (size > MAX_BODY_BYTES) throw new Error('body too large');
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

/** A body some middleware (express.urlencoded, express.json) already parsed, as bytes again. */
function reencode(body: unknown, contentType: string): string | Buffer | null {
  if (body === undefined || body === null) return null;
  if (typeof body === 'string' || Buffer.isBuffer(body)) return body;
  if (typeof body !== 'object') return null;
  if (contentType.includes('application/x-www-form-urlencoded')) {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(body as Record<string, unknown>)) {
      for (const v of Array.isArray(value) ? value : [value]) params.append(key, String(v));
    }
    return params.toString();
  }
  if (contentType.includes('json')) return JSON.stringify(body);
  return null;
}

/**
 * A Fetch `Request` for a Node request. The URL is built on `origin` (the issuer),
 * not on the Host header, so a proxy cannot change where redirects point.
 */
export async function requestFromNode(req: NodeRequest, origin: string): Promise<Request> {
  const url = new URL(req.originalUrl ?? req.url ?? '/', origin);
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    for (const v of Array.isArray(value) ? value : [value]) headers.append(key, v);
  }
  const method = (req.method ?? 'GET').toUpperCase();
  let body: string | Buffer | null = null;
  if (method !== 'GET' && method !== 'HEAD') {
    // body-parser sets `req.body = {}` even for a type it does not parse, and leaves
    // the stream unread. Read the stream unless a parser actually consumed it.
    const consumed = (req as { _body?: boolean })._body === true || req.readableEnded;
    body = consumed ? reencode(req.body, headers.get('content-type') ?? '') : await readStream(req);
    headers.delete('content-length');
  }
  return new Request(url, { method, headers, body: body === null ? undefined : new Uint8Array(body instanceof Buffer ? body : Buffer.from(body)) });
}

export async function writeNodeResponse(response: Response, res: ServerResponse): Promise<void> {
  res.statusCode = response.status;
  const cookies = response.headers.getSetCookie();
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() !== 'set-cookie') res.setHeader(key, value);
  });
  if (cookies.length > 0) res.setHeader('Set-Cookie', cookies);
  res.end(Buffer.from(await response.arrayBuffer()));
}

/**
 * Express or `node:http` middleware for the OAuth routes. Requests it does not
 * own go to `next` (or get a 404 without one).
 */
export function nodeHandler(agentCredentials: AgentCredentials) {
  const origin = String(agentCredentials.authorizationServerMetadata().issuer);
  return async (req: NodeRequest, res: ServerResponse, next?: Next): Promise<void> => {
    try {
      const response = await agentCredentials.handle(await requestFromNode(req, origin));
      if (response) return await writeNodeResponse(response, res);
      if (next) return next();
      res.statusCode = 404;
      res.end();
    } catch (error) {
      if (next) return next(error);
      res.statusCode = 500;
      res.end();
    }
  };
}

/** `authenticate` for a Node request. Only the headers are read. */
export function authenticateNode(
  agentCredentials: AgentCredentials,
  req: NodeRequest,
  resource?: string,
): Promise<AuthenticateResult> {
  const origin = String(agentCredentials.authorizationServerMetadata().issuer);
  const headers = new Headers();
  const authorization = req.headers.authorization;
  if (authorization) headers.set('Authorization', authorization);
  return agentCredentials.authenticate(new Request(new URL(req.originalUrl ?? req.url ?? '/', origin), { headers }), resource);
}
