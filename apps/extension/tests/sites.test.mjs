import test from 'node:test';
import assert from 'node:assert/strict';
import { sitePattern, hasSite, syncSites, installInTab } from '../src/sites.js';
test('site permission translation grants exactly one HTTPS host, including all its ports', () => {
  assert.equal(sitePattern('https://localhost:58090/login?secret=removed'), 'https://localhost/*');
  assert.equal(sitePattern('https://login.example.test/path'), 'https://login.example.test/*');
  assert.equal(sitePattern('https://[::1]:58090/'), 'https://[::1]/*');
  assert.throws(() => sitePattern('http://example.test/'), /HTTPS/);
  assert.throws(() => sitePattern('chrome://extensions'), /HTTPS/);
});
test('Chrome grants are the only source of truth, not activeTab or a copied allowlist', async () => {
  let origins = []; const calls = [];
  const chrome = { permissions: { getAll: async () => ({ origins }) }, webNavigation: { getFrame: async () => ({ url: 'https://example.test/login', documentId: 'current' }) }, scripting: { executeScript: async value => calls.push(value) } };
  assert.equal(await hasSite(chrome, 'https://example.test/login'), false);
  await assert.rejects(installInTab(chrome, 5), /permission/); assert.equal(calls.length, 0);
  origins = ['https://example.test/*'];
  assert.equal(await hasSite(chrome, 'https://sub.example.test/login'), false);
  await installInTab(chrome, 5);
  assert.deepEqual(calls[0].target, { tabId: 5, documentIds: ['current'] });
  origins = []; await assert.rejects(installInTab(chrome, 5), /permission/);
  assert.equal(calls.length, 1, 'revocation prevents reinjection');
});
test('registration converges after host grants and removal without persistent side state', async () => {
  let origins = [], registration;
  const locks = { request: (_, run) => run() };
  const chrome = { permissions: { getAll: async () => ({ origins }) }, scripting: {
    getRegisteredContentScripts: async () => registration ? [registration] : [],
    registerContentScripts: async ([value]) => { registration = value; },
    updateContentScripts: async ([value]) => { registration = value; },
    unregisterContentScripts: async () => { registration = null; }
  } };
  await syncSites(chrome, locks); assert.equal(registration, undefined);
  origins = ['https://example.test/*']; await syncSites(chrome, locks);
  assert.deepEqual(registration.matches, origins); assert.equal(registration.allFrames, false);
  assert.equal(registration.world, 'ISOLATED');
  origins = ['https://other.test/*']; await syncSites(chrome, locks); assert.deepEqual(registration.matches, origins);
  origins = []; await syncSites(chrome, locks); assert.equal(registration, null);
});
