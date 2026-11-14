import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, chooser, closed } from './fixture.mjs';

const titles = () => [...document.querySelectorAll('.match .name')].map(node => node.textContent);
test('1024 native matches use bounded DOM windows, local filtering and correct deep keyboard selection in both surfaces', { timeout: 90000 }, async () => {
  const env = await fixture({ matches: 1024 }); const { site, popup } = env;
  try {
    await popup.locator('#pairing-code').fill(env.info.code); await popup.locator('#pair').click();
    await popup.locator('#login-filter').waitFor();
    await popup.locator('#login-count').filter({ hasText: '1024 logins' }).waitFor();
    assert.ok(await popup.locator('.match').count() <= 9, 'full result is not rendered into DOM');
    assert.equal(await popup.locator('.match').first().getAttribute('aria-setsize'), '1024');
    await popup.locator('#matches').evaluate(node => { node.scrollTop = node.scrollHeight; });
    await popup.waitForFunction(() => Number(document.querySelector('.match')?.getAttribute('aria-posinset')) > 1000);
    assert.ok(await popup.locator('.match').count() <= 9);
    await popup.locator('#login-filter').fill('  PERSON-0999@EXAMPLE.TEST  ');
    await popup.locator('#login-count').filter({ hasText: '1 of 1024' }).waitFor();
    assert.deepEqual(await popup.evaluate(titles), ['Account 0999']);
    assert.equal(await popup.locator('#matches').evaluate(node => node.scrollTop), 0);
    await popup.locator('#login-filter').fill('not-a-login');
    await popup.locator('#login-empty').waitFor();
    await popup.locator('#login-filter').press('Enter');
    assert.equal(await popup.locator('.match').count(), 0);
    assert.equal(await site.locator('[name=password]').inputValue(), '', 'empty filtered selection cannot fill');
    assert.equal((await popup.evaluate(() => chrome.storage.local.get('autofillUsage'))).autofillUsage, undefined, 'filter/scroll never record use');
    await popup.locator('#login-filter').fill('');
    await popup.locator('#login-count').filter({ hasText: '1024 logins' }).waitFor();
    await popup.locator('#login-filter').press('End');
    const selected = popup.locator('.match[aria-selected=true]');
    assert.equal(await selected.getAttribute('aria-posinset'), '1024');
    await popup.locator('#login-filter').press('PageUp');
    assert.equal(await popup.locator('.match[aria-selected=true]').getAttribute('aria-posinset'), '1019');
    await popup.locator('#login-filter').press('PageDown');
    assert.equal(await selected.getAttribute('aria-posinset'), '1024');
    const lastUsername = await selected.locator('.user').textContent();
    assert.ok(await popup.locator('.match').count() <= 9);
    await popup.locator('#login-filter').press('Enter');
    await popup.locator('#notice').filter({ hasText: 'Login filled' }).waitFor();
    assert.equal(await site.locator('[name=username]').inputValue(), lastUsername, 'deep filtered index maps to the selected native item');
    await popup.evaluate(async () => {
      const { syncSites, installInTab } = await import('./sites.js');
      await syncSites(chrome, navigator.locks); await installInTab(chrome, (await chrome.tabs.query({}))[0].id);
    });
    await site.bringToFront(); await site.locator('[name=username]').click();
    const picker = await chooser(site); await picker.locator('#login-filter').waitFor();
    await picker.locator('#login-count').filter({ hasText: '1024' }).waitFor();
    assert.ok(await picker.locator('.match').count() <= 8);
    await picker.locator('#login-filter').fill('account 0999');
    await picker.locator('#login-count').filter({ hasText: '1 из 1024' }).waitFor();
    assert.deepEqual(await picker.evaluate(titles), ['Account 0999']);
    await picker.locator('#login-filter').press('Enter');
    await closed(site);
    assert.equal(await site.locator('[name=username]').inputValue(), 'person-0999@example.test', 'filtered inline selection maps to the actual native item');
    assert.deepEqual(env.errors, []);
  } finally { await env.close(); }
});
