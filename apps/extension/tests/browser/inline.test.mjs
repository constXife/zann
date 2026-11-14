import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, chooser, closed } from './fixture.mjs';
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
test('document-bound inline chooser uses real Rust search/fill and refuses page-script gestures', { timeout: 90000 }, async () => {
  const env = await fixture(); const { site, popup } = env;
  try {
    await popup.locator('#pairing-code').fill(env.info.code);
    await popup.locator('#pair').click();
    await popup.locator('.match').first().waitFor();
    await popup.evaluate(async () => {
      const { syncSites, installInTab } = await import('./sites.js');
      await syncSites(chrome, navigator.locks);
      await installInTab(chrome, (await chrome.tabs.query({}))[0].id);
    });
    await site.setViewportSize({ width: 736, height: 720 });
    await site.bringToFront(); await site.locator('[name=username]').click();
    let frame = await chooser(site);
    await frame.waitForFunction(() => document.querySelector('.match') || document.getElementById('retry').hidden === false, null, { timeout: 10000 });
    assert.equal(await frame.locator('#status').textContent(), '', 'query must succeed');
    assert.equal(await frame.locator('.match').count(), 2, 'all native pages searched');
    await frame.waitForFunction(() => document.body.getBoundingClientRect().height < 180);
    await frame.waitForFunction(() => innerWidth === 320 && innerHeight === Math.ceil(document.body.getBoundingClientRect().height));
    assert.equal(await frame.locator('#brand svg').count(), 1);
    await site.setViewportSize({ width: 320, height: 640 });
    await frame.waitForFunction(() => innerWidth === 304 && document.documentElement.scrollWidth <= innerWidth);
    await site.setViewportSize({ width: 736, height: 720 });
    await frame.waitForFunction(() => innerWidth === 320);
    assert.equal(await frame.locator('footer').count(), 0);
    assert.equal(await frame.locator('#generate').isVisible(), false, 'login fields do not show the generator');
    assert.equal(await frame.locator('#totp').count(), 0, 'no permanent TOTP checkbox');
    assert.equal(await frame.locator('.match').first().evaluate(button => button.getBoundingClientRect().height), 48);
    assert.equal(await frame.locator('.copy').first().evaluate(copy => copy.firstElementChild.className), 'user');
    assert.equal(await site.locator('[name=password]').inputValue(), '', 'focus/query never fill');
    // Closed shadow prevents page selectors inspecting even the embedding UI.
    assert.equal(await site.locator('iframe[src*="inline.html"]').count(), 0);
    await frame.locator('.match').filter({ hasText: 'Example' }).evaluate(button => button.click());
    await site.evaluate(() => { window.postMessage({ type: 'fill', item_id: 'forged', gesture: true }, '*'); });
    assert.equal(await site.locator('[name=password]').inputValue(), '', 'untrusted script click cannot release');
    assert.equal((await popup.evaluate(() => chrome.storage.local.get('autofillUsage'))).autofillUsage, undefined, 'opening and synthetic clicks never record usage');
    await frame.locator('.match').filter({ hasText: 'Example' }).click();
    await site.waitForFunction(() => document.querySelector('[name=password]').value.length > 0);
    await closed(site);
    assert.equal(await site.locator('[name=username]').inputValue(), 'alice');
    assert.equal(await site.locator('[name=password]').inputValue(), 'password-sentinel');
    assert.equal(await site.locator('[name=otp]').inputValue(), '', 'login selection does not fill an unrelated OTP field');
    await site.locator('[name=password]').fill('untouched-password');
    await site.locator('[name=username]').fill('untouched-username');
    await site.locator('[name=otp]').click(); frame = await chooser(site);
    await frame.locator('.match').first().waitFor(); await frame.locator('.match').filter({ hasText: 'Example' }).click();
    await site.waitForFunction(() => /^\d{6}$/.test(document.querySelector('[name=otp]').value));
    await closed(site);
    assert.equal(await site.locator('[name=password]').inputValue(), 'untouched-password', 'OTP selection only writes the code');
    assert.equal(await site.locator('[name=username]').inputValue(), 'untouched-username');
    await site.evaluate(() => {
      const form = document.createElement('form'); form.id = 'otp-only';
      const input = document.createElement('input'); input.name = 'standalone-otp'; input.autocomplete = 'one-time-code';
      form.append(input); document.body.append(form);
    });
    await site.locator('[name=standalone-otp]').click(); frame = await chooser(site);
    await frame.locator('.match').first().waitFor(); await frame.locator('.match').filter({ hasText: 'Example' }).click();
    await site.waitForFunction(() => /^\d{6}$/.test(document.querySelector('[name=standalone-otp]').value));
    await closed(site);
    assert.equal(await site.locator('[name=password]').inputValue(), 'untouched-password');
    await site.evaluate(() => document.getElementById('otp-only').remove());
    // Escape, re-focus and keyboard choice use the same bound surface.
    await site.locator('[name=password]').fill('');
    frame = await chooser(site); await frame.locator('.match').first().waitFor();
    await site.locator('[name=password]').press('Enter');
    await site.waitForFunction(() => document.querySelector('[name=password]').value.length > 0);
    await closed(site);
    assert.ok(await site.locator('[name=password]').inputValue());
    await site.evaluate(() => document.querySelector('[name=password]').autocomplete = 'new-password');
    await site.locator('[name=username]').click(); frame = await chooser(site); await frame.locator('.match').first().waitFor();
    await frame.locator('#close').click();
    await site.locator('[name=password]').click(); frame = await chooser(site);
    await frame.locator('#generate').waitFor({ state: 'visible' });
    assert.equal(await frame.locator('.match').count(), 0, 'new-password fields do not offer saved passwords');
    await frame.locator('#generate').click(); await frame.locator('#use-generated').click();
    await site.waitForFunction(() => document.querySelector('[name=password]').value.length === 24);
    await closed(site);
    assert.equal((await site.locator('[name=password]').inputValue()).length, 24);
    await site.evaluate(() => document.querySelector('[name=password]').autocomplete = 'current-password');
    // Same-document navigation destroys old metadata/authority and reattaches
    // the adapter to the current URL, not the obsolete focus selection.
    await site.evaluate(() => history.pushState({}, '', '/new-login'));
    await wait(250);
    assert.equal(site.frames().filter(frame => frame.url().includes('/inline.html#')).length, 0);
    await site.locator('[name=username]').click(); frame = await chooser(site);
    await frame.locator('.match').first().waitFor();
    // Replaced nodes cannot receive an old selection's released secret.
    await site.evaluate(() => { document.querySelector('form').innerHTML = '<input name="replacement" type="password">'; });
    await wait(100); assert.equal(await site.locator('[name=replacement]').inputValue(), '');
    assert.equal(site.frames().filter(frame => frame.url().includes('/inline.html#')).length, 0);
    // A native transport failure after chooser admission is a recoverable UI
    // error, not an iframe-admission refusal that disconnects the chooser.
    await env.worker.evaluate(() => { globalThis.__failNextNative = true; });
    await site.locator('[name=replacement]').click(); frame = await chooser(site);
    await frame.locator('#retry').waitFor({ state: 'visible' });
    assert.equal(await frame.locator('#generate').isVisible(), false);
    await frame.locator('#retry').click(); await frame.locator('.match').first().waitFor();
    const stored = await popup.evaluate(() => chrome.storage.local.get(null));
    assert.deepEqual(Object.keys(stored).sort(), ['autofillUsage', 'identity']);
    assert.deepEqual(env.errors, []);
  } finally { await env.close(); }
});
