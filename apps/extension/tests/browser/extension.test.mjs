import test from 'node:test';
import { tmpdir } from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { fixture } from './fixture.mjs';

test('Chromium popup uses real WASM, native host and daemon for pairing, fill, capture and generation', { timeout: 90000 }, async () => {
  const env = await fixture(); const { site, popup } = env;
  try {
    await popup.locator('#pairing').waitFor();
    assert.equal(await popup.locator('#workspace').isVisible(), false, 'setup shows only the connection task');
    await popup.locator('body').screenshot({ path: path.join(tmpdir(), 'zann-popup-connect.png') });
    const wrong = env.info.code === '123456' ? '654321' : '123456';
    await popup.locator('#pairing-code').fill(wrong);
    await popup.locator('#pair').click();
    await popup.locator('#notice[data-error]').waitFor();
    assert.equal((await popup.evaluate(() => chrome.storage.local.get('identity'))).identity.server, null, 'failed pairing never persists a provisional pin');
    assert.equal(await popup.locator('#pairing-code').inputValue(), '');
    await popup.locator('#pairing-code').fill(env.info.code);
    await popup.locator('#pair').click();
    await popup.waitForFunction(() => document.querySelectorAll('.match').length === 2);
    assert.equal(await popup.locator('#more').count(), 0, 'no manual pagination');
    assert.equal(await popup.locator('#site-title').textContent(), 'example.test');
    assert.equal(await popup.locator('#frame').isVisible(), false, 'page sections are optional advanced controls');
    assert.equal(await popup.locator('#form').isVisible(), false, 'one form needs no selector');
    await popup.locator('body').screenshot({ path: path.join(tmpdir(), 'zann-popup-logins.png') });
    assert.equal(await site.locator('[name=password]').inputValue(), '', 'no fill on load/query');
    await popup.locator('#totp').check(); await popup.locator('.match').filter({ hasText: 'Example' }).click();
    await popup.waitForFunction(() => document.getElementById('notice').textContent.includes('Login filled'));
    assert.equal(await site.locator('[name=username]').inputValue(), 'alice');
    assert.equal(await site.locator('[name=password]').inputValue(), 'password-sentinel');
    assert.match(await site.locator('[name=otp]').inputValue(), /^\d{6}$/);
    const usageBeforeSave = (await popup.evaluate(() => chrome.storage.local.get('autofillUsage'))).autofillUsage;
    await site.locator('[name=username]').fill('browser-user'); await site.locator('[name=password]').fill('captured-browser-sentinel');
    await popup.locator('#tab-save').click(); await popup.locator('#capture').click();
    await popup.locator('#save-login').waitFor({ state: 'visible' });
    await popup.locator('#title').fill('Captured from Chromium');
    await popup.locator('#save-login button[type=submit]').click();
    await popup.waitForFunction(() => document.getElementById('notice').textContent.includes('Login saved'));
    assert.equal(await popup.locator('#password').inputValue(), '');
    await popup.locator('#tab-generate').click(); await popup.locator('#generate-password').click();
    const generated = await popup.locator('#generated').inputValue(); assert.equal(generated.length, 24);
    await popup.locator('#use-generated').click();
    await popup.waitForFunction(() => document.getElementById('notice').textContent.includes('Password filled'));
    assert.equal(await site.locator('[name=password]').inputValue(), generated);
    const stored = await popup.evaluate(() => chrome.storage.local.get(null));
    assert.deepEqual(Object.keys(stored).sort(), ['autofillUsage', 'identity']);
    assert.equal(stored.autofillUsage, usageBeforeSave, 'save and generation do not count as successful credential fills');
    assert.deepEqual(Object.keys(stored.identity).sort(), ['seed','server','version']);
    assert.equal(stored.identity.server, env.info.server);
    assert.equal(await popup.locator('#pairing-code').inputValue(), '');
    await popup.reload();
    await popup.locator('.match').first().waitFor();
    assert.equal((await popup.evaluate(() => chrome.storage.local.get('identity'))).identity.server, env.info.server, 'reopening uses durable trust without another code');
    await popup.locator('#refresh').click();
    await popup.waitForFunction(() => document.querySelectorAll('.match').length === 3);
    await popup.locator('body').screenshot({ path: path.join(tmpdir(), 'zann-extension-popup.png') });
    // A same-document SPA URL change invalidates the old popup target.
    await site.evaluate(() => history.pushState({}, '', '/different'));
    await popup.waitForFunction(() => document.getElementById('page-title').textContent.includes('Page changed'));
    assert.equal(await popup.locator('.match').count(), 0, 'navigation clears results immediately');
    assert.equal(await site.locator('[name=password]').inputValue(), generated);
    // Stale references cannot be used after an SPA replaces its form nodes.
    await popup.locator('#retry-page').click(); await popup.locator('.match').first().waitFor();
    await site.evaluate(() => { document.querySelector('form').innerHTML = '<input name="replacement" type="password">'; });
    await popup.locator('.match').first().click();
    await popup.waitForFunction(() => document.getElementById('page-message').textContent.includes('Form changed'));
    assert.equal(await site.locator('[name=replacement]').inputValue(), '');
    // Cross-origin frame selection is refused by canonical Rust policy.
    await popup.locator('#retry-page').click(); await popup.locator('.match').first().waitFor();
    // Render a listbox in this test only: headless macOS's native popup menu
    // does not receive CDP keys. Actual option clicks still produce isTrusted.
    assert.ok(await popup.locator('#frame option').count() >= 2);
    await popup.locator('#page-target summary').click();
    await popup.locator('#frame').evaluate(select => { select.size = select.options.length; });
    await popup.locator('#frame option').filter({ hasText: 'evil.test' }).first().click();
    await popup.locator('#frame').evaluate(select => { select.size = 0; });
    await popup.locator('#page-issue').waitFor();
    assert.match(await popup.locator('#page-message').textContent(), /same HTTPS website/);
    assert.equal(await popup.locator('#connection').textContent(), 'Connected', 'page refusal is not a lost native connection');
    assert.equal(await popup.locator('.match').count(), 0);

    // Open shadow forms work after explicit refresh; hidden decoys are excluded.
    await site.evaluate(() => {
      const host = document.createElement('div'); document.body.append(host);
      host.attachShadow({ mode: 'open' }).innerHTML = '<form><input name="shadow-user" autocomplete="username"><input name="shadow-password" type="password" autocomplete="current-password"><input name="hidden-decoy" type="password" style="display:none"></form>';
    });
    await popup.locator('#retry-page').click(); await popup.locator('.match').first().waitFor();
    assert.equal(await popup.locator('.match').first().isDisabled(), true, 'multiple forms require an explicit choice');
    await popup.locator('#form').evaluate(select => { select.size = select.options.length; });
    await popup.locator('#form option').last().click();
    await popup.locator('#form').evaluate(select => { select.size = 0; });
    await popup.locator('.match').filter({ hasText: 'Example' }).click();
    await popup.waitForFunction(() => document.getElementById('notice').textContent.includes('Login filled'));
    assert.equal(await site.locator('[name=shadow-password]').inputValue(), 'password-sentinel');
    assert.equal(await site.locator('[name=hidden-decoy]').inputValue(), '');
    // Browser error pages are a page-only state, not a lost native pairing.
    await site.route('https://example.test/unavailable', route => route.abort('failed'));
    await assert.rejects(site.goto('https://example.test/unavailable'), /ERR_FAILED/);
    await popup.reload(); await popup.locator('#page-issue').waitFor();
    assert.equal(await popup.locator('#connection').textContent(), 'Connected');
    assert.equal(await popup.locator('#workspace').isVisible(), false);
    assert.equal(await popup.locator('#pairing').isVisible(), false);
    assert.doesNotMatch(await popup.locator('body').textContent(), /Frame with ID|showing error page/);
    await popup.locator('body').screenshot({ path: path.join(tmpdir(), 'zann-popup-unavailable.png') });
    await popup.locator('#settings-toggle').click(); await popup.locator('#settings').waitFor();
    assert.equal(await popup.locator('#forget').isVisible(), true, 'management stays accessible on an unavailable page');
    await popup.locator('#settings-toggle').click();
    await site.goto('https://example.test/login'); await popup.locator('#retry-page').click();
    await popup.locator('.match').first().waitFor();
    assert.equal(await site.locator('[name=password]').inputValue(), '', 'retry never replays a prior fill');
    assert.deepEqual(env.errors, []);
  } finally { await env.close(); }
});
