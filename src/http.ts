const NO_STORE = { 'Cache-Control': 'no-store', Pragma: 'no-cache' };

/** Token, revocation, registration, and metadata are called from other origins (browser-based Agents). */
export const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type, MCP-Protocol-Version',
  'Access-Control-Max-Age': '86400',
};

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...NO_STORE, ...headers },
  });
}

export function oauthError(
  error: string,
  description: string,
  status = 400,
  headers: Record<string, string> = {},
): Response {
  return json({ error, error_description: description }, status, { ...CORS_HEADERS, ...headers });
}

export function preflight(): Response {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

export function redirect(location: string, cookies: string[] = []): Response {
  const headers = new Headers({ Location: location, ...NO_STORE, 'Referrer-Policy': 'no-referrer' });
  for (const cookie of cookies) headers.append('Set-Cookie', cookie);
  return new Response(null, { status: 302, headers });
}

/** Pages a person sees. Never framed, no scripts, forms post only to this origin. */
export function html(body: string, status = 200, cookies: string[] = []): Response {
  const headers = new Headers({
    'Content-Type': 'text/html; charset=utf-8',
    ...NO_STORE,
    'Content-Security-Policy':
      "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  });
  for (const cookie of cookies) headers.append('Set-Cookie', cookie);
  return new Response(body, { status, headers });
}

export function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get('Cookie');
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return null;
}

export function cookie(
  name: string,
  value: string,
  { path, maxAge, secure }: { path: string; maxAge: number; secure: boolean },
): string {
  return [
    `${name}=${encodeURIComponent(value)}`,
    `Path=${path}`,
    `Max-Age=${maxAge}`,
    'HttpOnly',
    'SameSite=Lax',
    ...(secure ? ['Secure'] : []),
  ].join('; ');
}

const MAX_BODY_BYTES = 16 * 1024;

async function readBody(request: Request): Promise<string | null> {
  const length = Number(request.headers.get('Content-Length') ?? '0');
  if (length > MAX_BODY_BYTES) return null;
  const text = await request.text();
  return text.length > MAX_BODY_BYTES ? null : text;
}

/** `application/x-www-form-urlencoded` body. Null when too large. */
export async function readForm(request: Request): Promise<URLSearchParams | null> {
  const text = await readBody(request);
  return text === null ? null : new URLSearchParams(text);
}

/** JSON object body. Null when too large or not an object. */
export async function readJsonObject(request: Request): Promise<Record<string, unknown> | null> {
  const text = await readBody(request);
  if (text === null) return null;
  try {
    const value = JSON.parse(text) as unknown;
    return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
