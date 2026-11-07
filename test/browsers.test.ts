import { describe, expect, it } from 'vitest';
import { agentRedirect, authorizePath, connect, consentFlowId, exchange, flowCookie, get, identityToken, pkce, post, returnFromDelegate, setup, start } from './helpers';

/** Follow Delegate back to the callback from a browser holding `cookie` (none = another browser). */
async function back(h: ReturnType<typeof setup>, delegateUrl: URL, cookie?: string) {
  const token = await identityToken({ nonce: delegateUrl.searchParams.get('nonce') });
  const state = delegateUrl.searchParams.get('state')!;
  return (await h.agents.handle(get(`/oauth/callback?${new URLSearchParams({ delegate_token: token, state })}`, cookie)))!;
}

describe('phones and several tabs', () => {
  it('lets two attempts started in one browser both finish (tapping Connect twice)', async () => {
    const h = setup();
    const p1 = await pkce();
    const first = await start(h, { code_challenge: p1.challenge });
    const p2 = await pkce();
    const res2 = (await h.agents.handle(get(authorizePath({ code_challenge: p2.challenge }), first.cookie)))!;
    const cookie = flowCookie(res2)!;
    expect(cookie).toContain(first.state); // both flows are bound to this browser
    const page = await back(h, first.delegateUrl, cookie);
    expect(page.status).toBe(200);
    expect(await page.text()).toContain('wants to act as you');
  });

  it('offers to continue when sign-in comes back to another browser, then asks for consent with a warning', async () => {
    const h = setup();
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge });
    const offer = await back(h, s.delegateUrl); // no cookie: a different browser
    expect(offer.status).toBe(400);
    expect(offer.headers.get('Location')).toBeNull(); // never finished automatically
    const html = await offer.text();
    expect(html).toContain('Continue in this browser');
    const resumeUrl = new URL(/href="([^"]+)"/.exec(html)![1].replace(/&amp;/g, '&'));
    expect(resumeUrl.pathname).toBe('/oauth/resume');

    // The original state is used up.
    expect((await returnFromDelegate(h, s)).status).toBe(400);

    const resumed = (await h.agents.handle(get(resumeUrl.pathname + resumeUrl.search)))!;
    expect(resumed.status).toBe(302);
    const delegateUrl = new URL(resumed.headers.get('Location')!);
    const cookie = flowCookie(resumed)!;
    expect(cookie).toContain(delegateUrl.searchParams.get('state'));
    // The resume link works once.
    expect((await h.agents.handle(get(resumeUrl.pathname + resumeUrl.search)))!.status).toBe(400);

    const consentPage = await back(h, delegateUrl, cookie);
    expect(consentPage.status).toBe(200);
    const page = await consentPage.text();
    expect(page).toContain('started in another browser or tab');
    const done = (await h.agents.handle(
      post('/oauth/consent', { flow: consentFlowId(page), decision: 'allow', scope: ['people:read', 'people:write'] }, flowCookie(consentPage)!),
    ))!;
    const code = agentRedirect(done).get('code')!;
    expect((await exchange(h, code, p)).res.status).toBe(200);
  });

  it('a resumed flow always shows consent, even when the agent is already approved', async () => {
    const h = setup();
    await connect(h, { scope: 'people:read' });
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge, scope: 'people:read' });
    expect((await returnFromDelegate(h, s)).status).toBe(302); // same browser: remembered approval, straight back
    const s2 = await start(h, { code_challenge: p.challenge, scope: 'people:read' });
    const html = await (await back(h, s2.delegateUrl)).text();
    const resumeUrl = new URL(/href="([^"]+)"/.exec(html)![1].replace(/&amp;/g, '&'));
    const resumed = (await h.agents.handle(get(resumeUrl.pathname + resumeUrl.search)))!;
    const page = await back(h, new URL(resumed.headers.get('Location')!), flowCookie(resumed)!);
    expect(page.status).toBe(200);
    expect(await page.text()).toContain('started in another browser or tab');
  });

  it('says an expired attempt expired', async () => {
    const h = setup();
    const p = await pkce();
    const s = await start(h, { code_challenge: p.challenge });
    h.tick(16 * 60);
    const res = await returnFromDelegate(h, s);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain('expired');
  });

  it('gives buttons a text colour, so Cancel is visible in dark mode', async () => {
    const h = setup();
    const p = await pkce();
    const html = await (await returnFromDelegate(h, await start(h, { code_challenge: p.challenge }))).text();
    expect(html).toContain('color-scheme:light');
    expect(html).toMatch(/button,\.button\{[^}]*color:#1d1d1f/);
  });
});
