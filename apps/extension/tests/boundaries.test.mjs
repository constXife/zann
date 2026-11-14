import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { BrowserPage, PageError } from '../src/browser.js';
import { loadIdentity, pinIdentity, forgetIdentity, withIdentity } from '../src/identity.js';
import { NativeConnection } from '../src/native.js';

const frame = (url, documentId = 'document-a') => ({ frameId: 0, url, documentId });
test('document replacement and same-document URL changes refuse injection', async () => {
  let frames = [frame('https://example.test/login')], injections = 0;
  const chrome = { tabs: { query: async () => [{ id: 12 }] }, webNavigation: { getAllFrames: async () => frames }, scripting: { executeScript: async () => { injections++; return [{ documentId: 'document-a', result: { ok: true } }]; } } };
  const page = new BrowserPage(chrome, (top, frame) => JSON.stringify({ top_level_url: top, frame_url: frame }));
  const target = page.select(await page.frames(), 0);
  await page.fields(target, 'scan'); assert.equal(injections, 1);
  frames = [frame('https://example.test/login', 'document-b')];
  await assert.rejects(page.fields(target, 'fill', { value: 'sentinel' }), /Page changed/);
  frames = [frame('https://example.test/other')];
  await assert.rejects(page.fields(target, 'capture'), /Page changed/);
  assert.equal(injections, 1);
});
test('identity storage is trusted-only and malformed state is never repaired implicitly', async () => {
  let restricted = false, writes = 0;
  const chrome = { storage: { local: { setAccessLevel: async value => { assert.equal(value.accessLevel, 'TRUSTED_CONTEXTS'); restricted = true; }, get: async () => { assert.ok(restricted); return { identity: { version: 2, seed: 'broken' } }; }, set: async () => writes++ } } };
  await assert.rejects(loadIdentity(chrome, () => { throw new Error('must not regenerate'); }, { request: (_, operation) => operation() }), /Invalid pairing/);
  assert.equal(writes, 0);
});
test('native disconnect after dispatch rejects without replay', async () => {
  const listeners = {}; let posted = 0, freed = 0;
  const event = name => ({ addListener: fn => { listeners[name] = fn; } });
  const port = { onMessage: event('message'), onDisconnect: event('disconnect'), postMessage: () => { posted++; queueMicrotask(() => listeners.disconnect()); }, disconnect: () => {} };
  const chrome = { runtime: { connectNative: () => port } };
  const client = { request: () => '{}', free: () => freed++ };
  const connection = new NativeConnection(chrome, client);
  await assert.rejects(connection.request({ method: 'fill' }), /closed/i);
  assert.equal(posted, 1); assert.equal(freed, 1);
  await assert.rejects(connection.request({ method: 'fill' }), /closed/i);
  assert.equal(posted, 1);
});
test('shipping manifest declares opt-in HTTPS access and only the chooser is web accessible', async () => {
  const manifest = JSON.parse(await readFile(new URL('../manifest.json', import.meta.url)));
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(manifest.permissions.slice().sort(), ['activeTab', 'nativeMessaging', 'scripting', 'storage', 'webNavigation'].sort());
  for (const key of ['host_permissions', 'content_scripts', 'externally_connectable']) assert.equal(manifest[key], undefined);
  assert.deepEqual(manifest.optional_host_permissions, ['https://*/*']);
  assert.deepEqual(manifest.web_accessible_resources, [{ resources: ['inline.html'], matches: ['https://*/*'], use_dynamic_url: true }]);
  assert.deepEqual(manifest.background, { service_worker: 'background.js', type: 'module' });
  assert.match(manifest.content_security_policy.extension_pages, /script-src 'self' 'wasm-unsafe-eval'/);
  assert.doesNotMatch(manifest.content_security_policy.extension_pages.replace('frame-ancestors https:;', ''), /https?:|unsafe-inline|'unsafe-eval'/);
});

test('concurrent popups share one identity and stale pin updates cannot undo an explicit forget', async () => {
  let stored, generated = 0, tail = Promise.resolve();
  const locks = { request: (_, operation) => { const next = tail.then(operation); tail = next.catch(() => {}); return next; } };
  const chrome = { storage: { local: { setAccessLevel: async () => {}, remove: async key => { assert.equal(key, 'autofillUsage'); }, get: async () => ({ identity: stored }), set: async ({ identity }) => { stored = structuredClone(identity); } } } };
  const generate = () => (++generated).toString(16).padStart(64, '0');
  const [first, second] = await Promise.all([loadIdentity(chrome, generate, locks), loadIdentity(chrome, generate, locks)]);
  assert.equal(first.seed, second.seed); assert.equal(generated, 1);
  const replacement = await forgetIdentity(chrome, first, generate, locks);
  assert.notEqual(replacement.seed, first.seed);
  await assert.rejects(pinIdentity(chrome, second, 'a'.repeat(64), locks), /changed in another popup/);
  assert.equal(stored.seed, replacement.seed); assert.equal(stored.server, null);
});


test('an authenticated pin cannot be replaced without explicit forget', async () => {
  let stored = { version: 1, seed: '1'.repeat(64), server: null };
  const chrome = { storage: { local: { get: async () => ({ identity: stored }), set: async ({ identity }) => { stored = structuredClone(identity); } } } };
  const locks = { request: (_, operation) => operation() };
  await pinIdentity(chrome, structuredClone(stored), 'a'.repeat(64), locks);
  const trusted = structuredClone(stored);
  await assert.rejects(pinIdentity(chrome, trusted, 'b'.repeat(64), locks), /Forget the existing connection/);
  assert.equal(stored.server, trusted.server);
});


test('a browser error document refuses inspection before any field read', async () => {
  let inspections = 0;
  const chrome = { tabs: { query: async () => [{ id: 12 }] }, webNavigation: { getAllFrames: async () => [{ ...frame('https://example.test'), errorOccurred: true }] }, scripting: { executeScript: async () => inspections++ } };
  const page = new BrowserPage(chrome, () => { throw new Error('admission must not run'); });
  await assert.rejects(page.frames(), error => error instanceof PageError && /hasn’t loaded/.test(error.message));
  assert.equal(inspections, 0);
});

test('browser capability and Rust admission failures keep their causes behind readable page errors', async () => {
  const original = new Error('Frame with ID 0 is showing error page');
  const chrome = { tabs: { query: async () => [{ id: 12 }] }, webNavigation: { getAllFrames: async () => [frame('https://example.test')] }, scripting: { executeScript: async () => { throw original; } } };
  const page = new BrowserPage(chrome, (top, frame) => JSON.stringify({ top_level_url: top, frame_url: frame }));
  await assert.rejects(page.fields(page.select(await page.frames(), 0), 'scan'), error => error instanceof PageError && error.cause === original && !error.message.includes('ID 0'));
  const refused = new BrowserPage(chrome, () => { throw original; });
  assert.throws(() => refused.select({ top: frame('https://example.test'), frames: [frame('https://example.test')] }, 0), error => error instanceof PageError && error.cause === original);
});


test('a late usage update cannot recreate history after Forget replaces the identity', async () => {
  let stored = { version: 1, seed: '1'.repeat(64), server: 'a'.repeat(64) }, removed = 0, writes = 0;
  const old = structuredClone(stored);
  const chrome = { storage: { local: { setAccessLevel: async () => {}, get: async () => ({ identity: stored }), remove: async key => { assert.equal(key, 'autofillUsage'); removed++; }, set: async ({ identity }) => { stored = identity; } } } };
  const locks = { request: (_, operation) => operation() };
  await forgetIdentity(chrome, old, () => '2'.repeat(64), locks);
  await assert.rejects(withIdentity(chrome, old, locks, async () => writes++), /changed in another popup/);
  assert.equal(removed, 1); assert.equal(writes, 0);
});


test('identity-scoped metadata read-modify-write operations serialize instead of losing a concurrent fill', async () => {
  const identity = { version: 1, seed: '1'.repeat(64), server: 'a'.repeat(64) };
  let tail = Promise.resolve(), revision = 0;
  const locks = { request: (_, operation) => { const next = tail.then(operation); tail = next.catch(() => {}); return next; } };
  const chrome = { storage: { local: { get: async () => ({ identity }) } } };
  const update = () => withIdentity(chrome, identity, locks, async () => { const observed = revision; await Promise.resolve(); revision = observed + 1; });
  await Promise.all([update(), update()]);
  assert.equal(revision, 2);
});
