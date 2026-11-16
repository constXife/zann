import test from 'node:test';
import path from 'node:path';
import { tmpdir } from 'node:os';
import assert from 'node:assert/strict';
import { fixture } from './fixture.mjs';
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function prompt(env) {
  for (let i = 0; i < 150; i++) {
    const page = env.site.context().pages().find(page => page.url().includes('/passkey.html#'));
    if (page) { await page.locator('#choices button').first().waitFor(); return page; }
    await pause(50);
  }
  throw new Error('Passkey confirmation did not open.');
}
async function start(site, kind, allowed, extra = {}) {
  await site.evaluate(({ kind, allowed, extra }) => {
    globalThis.passkeyResult = null;
    const options = kind === 'create' ? { challenge: new Uint8Array(32).fill(7), rp: { id: 'example.test', name: 'Example' }, user: { id: new Uint8Array([1, 2, 3]), name: 'alice@example.test', displayName: 'Alice' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], authenticatorSelection: { residentKey: 'required', userVerification: 'discouraged' }, attestation: 'none' }
      : { challenge: new Uint8Array(32).fill(9), rpId: 'example.test', userVerification: 'discouraged' };
    if (allowed) options[kind === 'create' ? 'excludeCredentials' : 'allowCredentials'] = [{ type: 'public-key', id: Uint8Array.from(atob(allowed.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0)) }];
    Object.assign(options, extra);
    navigator.credentials[kind]({ publicKey: options }).then(value => {
      globalThis.passkeyResult = { ok: true, json: value.toJSON(), instance: value instanceof PublicKeyCredential };
      if (kind === 'create') globalThis.passkeySpki = value.response.getPublicKey();
    }, error => { globalThis.passkeyResult = { ok: false, name: error.name }; });
  }, { kind, allowed, extra });
}
test('WebAuthn registration and discoverable/allowCredentials assertions use real native crypto and trusted per-request confirmation', { timeout: 90000 }, async () => {
  const env = await fixture();
  try {
    const { popup, site } = env;
    await popup.locator('#pairing-code').fill(env.info.code); await popup.locator('#pair').click();
    await popup.locator('.match').first().waitFor();
    await popup.evaluate(async () => {
      const { syncSites, installInTab } = await import('./sites.js');
      await syncSites(chrome, navigator.locks); await installInTab(chrome, (await chrome.tabs.query({}))[0].id);
    });
    await site.bringToFront();
    await start(site, 'create'); let confirmation = await prompt(env);
    assert.equal(await confirmation.locator('#rp').textContent(), 'example.test');
    assert.equal(await confirmation.locator('#account').textContent(), 'alice@example.test');
    await confirmation.screenshot({ path: path.join(tmpdir(), 'zann-passkey-confirmation.png') });
    await confirmation.locator('#choices button').evaluate(button => button.click());
    await pause(150); assert.equal(await site.evaluate(() => passkeyResult), null, 'page-script clicks are not presence');
    await confirmation.locator('#choices button').click();
    await site.waitForFunction(() => globalThis.passkeyResult !== null);
    const created = await site.evaluate(() => passkeyResult);
    assert.equal(created.ok, true); assert.equal(created.instance, true);
    const id = created.json.id;
    assert.equal(created.json.response.transports[0], 'internal');
    for (const allowed of [undefined, id]) {
      await site.bringToFront(); await start(site, 'get', allowed); confirmation = await prompt(env);
      assert.equal(await site.evaluate(() => passkeyResult), null, 'unlocked vault cannot sign in the background');
      // More than the ordinary five-second frame deadline must remain usable.
      if (!allowed) await pause(5500);
      await confirmation.locator('#choices button').click(); await site.waitForFunction(() => globalThis.passkeyResult !== null);
      const assertion = await site.evaluate(() => passkeyResult); assert.equal(assertion.ok, true); assert.equal(assertion.json.id, id);
      const verified = await site.evaluate(async json => {
        const bytes = value => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
        const auth = bytes(json.response.authenticatorData), hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes(json.response.clientDataJSON)));
        const data = new Uint8Array(auth.length + hash.length); data.set(auth); data.set(hash, auth.length);
        // WebCrypto expects fixed-width P1363; WebAuthn emits ASN.1 DER.
        const der = bytes(json.response.signature); let at = 2;
        const scalar = () => { if (der[at++] !== 2) throw new Error('DER integer'); const n = der[at++], v = der.slice(at, at + n); at += n; return v[0] === 0 ? v.slice(1) : v; };
        const r = scalar(), s = scalar(), signature = new Uint8Array(64); signature.set(r, 32 - r.length); signature.set(s, 64 - s.length);
        const key = await crypto.subtle.importKey('spki', passkeySpki, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
        return { valid: await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, data), flags: auth[32], counter: [...auth.slice(33, 37)], client: JSON.parse(new TextDecoder().decode(bytes(json.response.clientDataJSON))) };
      }, assertion.json);
      assert.equal(verified.valid, true); assert.equal(verified.flags, 0x19); assert.deepEqual(verified.counter, [0, 0, 0, 0]);
      assert.equal(verified.client.origin, 'https://example.test'); assert.equal(verified.client.type, 'webauthn.get');
    }
    await site.bringToFront(); await start(site, 'create', id); await site.waitForFunction(() => globalThis.passkeyResult !== null);
    assert.equal((await site.evaluate(() => passkeyResult)).ok, false, 'excludeCredentials refuses duplication');
    await start(site, 'get', undefined, { rpId: 'evil.test' }); await site.waitForFunction(() => globalThis.passkeyResult !== null);
    assert.equal((await site.evaluate(() => passkeyResult)).ok, false);
    await start(site, 'get', undefined, { userVerification: 'required' }); await site.waitForFunction(() => globalThis.passkeyResult !== null);
    assert.equal((await site.evaluate(() => passkeyResult)).ok, false, 'UP alone must never claim UV');
    await start(site, 'get'); confirmation = await prompt(env); await confirmation.locator('#cancel').click();
    await site.waitForFunction(() => globalThis.passkeyResult !== null); assert.equal((await site.evaluate(() => passkeyResult)).ok, false);
    await site.reload();
    const cross = site.frames().find(frame => frame.url().startsWith('https://evil.test/'));
    await cross.waitForFunction(() => globalThis.__zannPasskeys === true);
    await start(cross, 'get'); await cross.waitForFunction(() => globalThis.passkeyResult !== null);
    assert.equal((await cross.evaluate(() => passkeyResult)).ok, false, 'privileged frame identity refuses cross-origin callers');
    assert.deepEqual(env.errors, []);
  } finally { await env.close(); }
});
