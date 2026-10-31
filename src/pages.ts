import type { ResolvedClient } from './clients';
import { escapeHtml } from './http';

const STYLE = `
*{box-sizing:border-box}
body{margin:0;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#1d1d1f;background:#f4f4f6}
main{max-width:30rem;margin:3rem auto;padding:2rem;background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.12)}
h1{font-size:1.3rem;line-height:1.3;margin:0 0 1rem}
p{margin:0 0 1rem}
.who{color:#555;font-size:.95rem}
.warn{background:#fff4e5;border:1px solid #f0c36d;border-radius:8px;padding:.75rem 1rem;font-size:.95rem}
fieldset{border:1px solid #ddd;border-radius:8px;margin:0 0 1rem;padding:.5rem 1rem}
legend{font-weight:600;padding:0 .25rem}
label{display:flex;gap:.6rem;align-items:flex-start;padding:.4rem 0}
label small{display:block;color:#666;font-family:ui-monospace,monospace;font-size:.8rem}
.new{color:#a15c00;font-size:.8rem;font-weight:600}
.actions{display:flex;gap:.75rem;justify-content:flex-end;margin-top:1.5rem}
button{font:inherit;padding:.6rem 1.2rem;border-radius:8px;border:1px solid #bbb;background:#fff;cursor:pointer}
button[value=allow]{background:#1d1d1f;color:#fff;border-color:#1d1d1f}
.fine{color:#666;font-size:.85rem;margin-top:1.5rem}
`;

function page(title: string, body: string): string {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${escapeHtml(title)}</title><style>${STYLE}</style></head><body><main>${body}</main></body></html>`;
}

export function errorPage(title: string, message: string): string {
  return page(title, `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>`);
}

function hostOf(uri: string): string {
  try {
    const url = new URL(uri);
    if (url.protocol === 'https:') return url.host;
    if (url.protocol === 'http:') return 'an app on this computer';
    return `an app on this device (${url.protocol}//)`;
  } catch {
    return uri;
  }
}

/** Who is asking, by what this Domain can actually verify. */
function describeAgent(client: ResolvedClient, redirectUri: string): { name: string; warning: string | null } {
  if (client.kind === 'registered') {
    return { name: `<strong>${escapeHtml(client.client_name ?? client.client_id)}</strong>`, warning: null };
  }
  if (client.kind === 'metadata') {
    const host = new URL(client.client_id).host;
    const name = client.client_name && client.client_name !== host ? `${escapeHtml(client.client_name)} from ` : '';
    return { name: `<strong>${name}${escapeHtml(host)}</strong>`, warning: null };
  }
  const label = client.client_name ? `an app calling itself “${escapeHtml(client.client_name)}”` : 'an app';
  return {
    name: `<strong>${label}</strong>`,
    warning: `This app registered itself, so no one has confirmed who made it. Its access will go to <strong>${escapeHtml(
      hostOf(redirectUri),
    )}</strong>. Only continue if you started connecting it yourself just now.`,
  };
}

export interface ConsentPageInput {
  domain: string;
  client: ResolvedClient;
  redirectUri: string;
  person: string;
  scopes: Array<{ name: string; description: string; isNew: boolean }>;
  flowId: string;
  action: string;
  maxAgeDays: number;
}

export function consentPage(input: ConsentPageInput): string {
  const agent = describeAgent(input.client, input.redirectUri);
  const domain = escapeHtml(input.domain);
  const scopes = input.scopes
    .map(
      (scope) =>
        `<label><input type="checkbox" name="scope" value="${escapeHtml(scope.name)}" checked><span>${escapeHtml(
          scope.description,
        )}${scope.isNew ? ' <span class="new">New</span>' : ''}<small>${escapeHtml(scope.name)}</small></span></label>`,
    )
    .join('');
  return page(
    `Connect an agent to ${input.domain}`,
    `<h1>${agent.name} wants to act as you on ${domain}</h1>
<p class="who">Signed in as <strong>${escapeHtml(input.person)}</strong></p>
${agent.warning ? `<p class="warn">${agent.warning}</p>` : ''}
<form method="post" action="${escapeHtml(input.action)}">
<input type="hidden" name="flow" value="${escapeHtml(input.flowId)}">
<fieldset><legend>It will be able to</legend>${scopes}</fieldset>
<p>${domain} still checks what your own access allows on every request, so the agent can never do more than you can.</p>
<div class="actions"><button type="submit" name="decision" value="deny">Cancel</button><button type="submit" name="decision" value="allow">Allow</button></div>
</form>
<p class="fine">This lasts until you disconnect the agent, or for up to ${input.maxAgeDays} days, whichever is first.</p>`,
  );
}
