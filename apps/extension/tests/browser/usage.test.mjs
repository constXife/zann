import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, chooser, closed } from './fixture.mjs';

async function history(popup) {
  return popup.evaluate(async () => (await chrome.storage.local.get('autofillUsage')).autofillUsage);
}
test('successful DOM fill ranks popup and inline consistently, survives reopen, and failures/Forget cannot recreate usage', { timeout: 90000 }, async () => {
  const env = await fixture(); const { popup, site } = env;
  try {
    await popup.locator('#pairing-code').fill(env.info.code); await popup.locator('#pair').click();
    await popup.locator('.match').first().waitFor();
    assert.equal(await history(popup), undefined, 'queries alone create no usage record');
    await popup.locator('.match').filter({ hasText: 'Second login' }).click();
    await popup.locator('#notice').filter({ hasText: 'Login filled' }).waitFor();
    const first = JSON.parse(await history(popup));
    assert.equal(first.entries.length, 1);
    assert.deepEqual(Object.keys(first.entries[0]).sort(), ['item_id', 'server_key', 'storage_id', 'vault_id']);
    assert.equal(first.entries[0].server_key, env.info.server);
    assert.equal(JSON.stringify(first).includes('password-sentinel'), false);
    assert.equal(JSON.stringify(first).includes('alice'), false);
    const secondId = first.entries[0].item_id;
    await popup.reload(); await popup.locator('.match').first().waitFor();
    assert.match(await popup.locator('.match').first().textContent(), /Second login/);
    await popup.locator('.match').filter({ hasText: 'Example' }).click();
    await popup.locator('#notice').filter({ hasText: 'Login filled' }).waitFor();
    const afterPopup = JSON.parse(await history(popup));
    assert.equal(afterPopup.entries.length, 2); assert.notEqual(afterPopup.entries[0].item_id, secondId);

    await popup.evaluate(async () => {
      const { syncSites, installInTab } = await import('./sites.js');
      await syncSites(chrome, navigator.locks);
      await installInTab(chrome, (await chrome.tabs.query({}))[0].id);
    });
    await site.bringToFront(); await site.locator('[name=username]').click();
    const picker = await chooser(site); await picker.locator('.match').first().waitFor();
    assert.match(await picker.locator('.match').first().textContent(), /Example/, 'inline reads popup history');
    await picker.locator('.match').filter({ hasText: 'Second login' }).click();
    await closed(site);
    await popup.bringToFront(); await popup.reload(); await popup.locator('.match').first().waitFor();
    assert.match(await popup.locator('.match').first().textContent(), /Second login/, 'popup reads inline history');
    const beforeFailure = await history(popup);
    assert.equal(JSON.parse(beforeFailure).entries[0].item_id, secondId);
    // Metadata persistence is ancillary: an error after confirmed DOM insertion
    // must report success-of-fill without claiming that insertion failed.
    await popup.evaluate(() => {
      const original = chrome.storage.local.set.bind(chrome.storage.local);
      globalThis.__restoreUsageStorage = () => { chrome.storage.local.set = original; };
      chrome.storage.local.set = values => Object.hasOwn(values, 'autofillUsage') ? Promise.reject(new Error('fixture storage write failure')) : original(values);
    });
    await popup.locator('.match').filter({ hasText: 'Example' }).click();
    await popup.locator('#notice').filter({ hasText: 'Fields filled. Local autofill history could not be saved.' }).waitFor();
    assert.equal(await site.locator('[name=password]').inputValue(), 'password-sentinel');
    assert.equal(await history(popup), beforeFailure);
    assert.equal(await popup.locator('#workspace').isVisible(), true);
    await popup.evaluate(() => globalThis.__restoreUsageStorage());
    await site.evaluate(() => { document.querySelector('form').innerHTML = '<input name="replacement" type="password">'; });
    await popup.locator('.match').filter({ hasText: 'Example' }).click();
    await popup.locator('#page-issue').waitFor();
    assert.equal(await history(popup), beforeFailure, 'failed insertion does not change recency');
    assert.equal(await site.locator('[name=replacement]').inputValue(), '');

    await popup.locator('#settings-toggle').click(); await popup.locator('#forget').click();
    await popup.locator('#pairing').waitFor();
    assert.equal(await history(popup), undefined, 'explicit Forget removes local activity metadata');
    assert.deepEqual(env.errors, []);
  } finally { await env.close(); }
});
