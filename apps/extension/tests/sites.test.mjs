import test from 'node:test';
import assert from 'node:assert/strict';
import { sitePattern, siteAccess, syncSites, installInTab } from '../src/sites.js';
test('site permission translation grants exactly one HTTPS host, including all its ports', () => {
  assert.equal(sitePattern('https://localhost:58090/login?secret=removed'), 'https://localhost/*');
  assert.equal(sitePattern('https://login.example.test/path'), 'https://login.example.test/*');
  assert.equal(sitePattern('https://[::1]:58090/'), 'https://[::1]/*');
  assert.throws(() => sitePattern('http://example.test/'), /HTTPS/);
  assert.throws(() => sitePattern('chrome://extensions'), /HTTPS/);
});
test('global suggestions and exact passkey grants are independent through revoke and reinjection', async () => {
  const global = 'https://*/*', exact = 'https://example.test/*';
  const frame = { url: 'https://example.test/login', documentId: 'current' };
  const registrations = new Map(), injections = [];
  let origins = [];
  const chrome = {
    permissions: { getAll: async () => ({ origins }) },
    webNavigation: { getFrame: async () => frame },
    scripting: {
      getRegisteredContentScripts: async () => [...registrations.values()],
      registerContentScripts: async ([script]) => { assert.ok(!registrations.has(script.id)); registrations.set(script.id, script); },
      updateContentScripts: async ([script]) => { assert.ok(registrations.has(script.id)); registrations.set(script.id, script); },
      unregisterContentScripts: async ({ ids }) => ids.forEach(id => registrations.delete(id)),
      executeScript: async script => { assert.deepEqual(script.target, { tabId: 5, documentIds: ['current'] }); injections.push(script.files[0]); }
    }
  };
  const locks = { request: (_, run) => run() };
  for (origins of [[], [exact], [exact, global], [global], [global, exact], [exact], []]) {
    await syncSites(chrome, locks);
    const any = origins.includes(global), local = origins.includes(exact);
    assert.deepEqual(await siteAccess(chrome, frame.url), { suggestions: any || local, passkeys: local });
    assert.deepEqual(await siteAccess(chrome, 'https://sub.example.test'), { suggestions: any, passkeys: false });
    assert.deepEqual(await siteAccess(chrome, 'http://example.test'), { suggestions: false, passkeys: false });
    const inline = registrations.get('zann-inline-sites');
    assert.deepEqual(inline?.matches, any ? [global] : local ? [exact] : undefined);
    if (inline) { assert.equal(inline.allFrames, false); assert.equal(inline.world, 'ISOLATED'); }
    for (const id of ['zann-passkey-main', 'zann-passkey-bridge']) {
      assert.deepEqual(registrations.get(id)?.matches, local ? [exact] : undefined);
    }
    injections.length = 0;
    await installInTab(chrome, 5);
    assert.deepEqual(injections, local ? ['passkey-isolated-content.js', 'passkey-main-content.js', 'content.js'] : any ? ['content.js'] : []);
  }
});

test('installing stops when the tab closes or navigation removes the target document', async () => {
  const frame = { url: 'https://example.test/login', documentId: 'original' };
  const chrome = {
    webNavigation: { getFrame: async () => { throw new Error('No tab with id: 5'); } },
    permissions: { getAll: async () => ({ origins: ['https://example.test/*'] }) },
    scripting: { executeScript: assert.fail }
  };
  await installInTab(chrome, 5);
  chrome.webNavigation.getFrame = async () => frame;
  const injections = [];
  chrome.scripting.executeScript = async ({ target, files }) => {
    assert.deepEqual(target.documentIds, ['original']);
    injections.push(...files);
    if (injections.length === 2) throw new Error('Frame with ID 0 was removed.');
  };
  await installInTab(chrome, 5);
  assert.deepEqual(injections, ['passkey-isolated-content.js', 'passkey-main-content.js']);

  const denied = new Error('Cannot access contents of the page.');
  chrome.scripting.executeScript = async () => { throw denied; };
  await assert.rejects(installInTab(chrome, 5), error => error === denied);
});

test('all-sites button requests only the optional HTTPS scope and reflects denial and revocation', async t => {
  const elements = new Map();
  const document = { getElementById(id) {
    if (!elements.has(id)) elements.set(id, { dataset: {}, addEventListener(type, fn) { this[type] = fn; } });
    return elements.get(id);
  } };
  const exact = 'https://example.test/*', broad = 'https://*/*';
  const origins = new Set([exact]), requests = [];
  let approve = false;
  const chrome = {
    tabs: { query: async () => [{ url: 'https://example.test/login' }] },
    permissions: {
      getAll: async () => ({ origins: [...origins] }),
      request: async permission => {
        requests.push(permission);
        if (approve) origins.add(permission.origins[0]);
        return approve;
      },
      remove: async permission => origins.delete(permission.origins[0]),
      onAdded: { addListener() {} }, onRemoved: { addListener() {} }
    }
  };
  globalThis.document = document;
  t.after(() => { delete globalThis.document; });
  const { siteSettings } = await import('../src/site-settings.js');
  await siteSettings(chrome);
  const button = elements.get('all-sites-toggle');
  await button.click({ isTrusted: false });
  assert.deepEqual(requests, []);
  await button.click({ isTrusted: true });
  assert.deepEqual(requests, [{ origins: [broad] }]);
  assert.equal(button.dataset.enabled, 'false');
  approve = true;
  await button.click({ isTrusted: true });
  assert.equal(button.dataset.enabled, 'true');
  await button.click({ isTrusted: true });
  assert.deepEqual([...origins], [exact]);
  assert.equal(button.dataset.enabled, 'false');
});
