import test from 'node:test';
import assert from 'node:assert/strict';
import { collectLogins } from '../src/search.js';
import { BrowserPage } from '../src/browser.js';

function setup() {
  let accepted = 0, freed = 0, calls = 0, closed = 0, checked = 0;
  const controller = new AbortController();
  const search = { request: () => JSON.stringify({ method: 'query', cursor: accepted || null }), accept_page: () => ++accepted === 3, matches_found: () => accepted, result: () => '{"items":[],"scope":{}}', free: () => freed++ };
  const connection = { request: async () => { calls++; return { status: 'matches', page: {} }; }, close: () => closed++ };
  const effects = { assertCurrent: async () => { checked++; }, onProgress: () => {}, clock: () => 0, signal: controller.signal };
  return { search, connection, effects, controller, stats: () => ({ accepted, freed, calls, closed, checked }) };
}
test('automatic search waits for every page and checks browser context on both sides of each reply', async () => {
  const env = setup(); const progress = []; env.effects.onProgress = pages => progress.push(pages);
  assert.deepEqual(await collectLogins(env.connection, env.search, env.effects), { items: [], scope: {} });
  assert.deepEqual(progress, [1,2,3]);
  assert.deepEqual(env.stats(), { accepted: 3, freed: 1, calls: 3, closed: 0, checked: 6 });
});
test('a disconnected later page is not retried and releases all partial search state', async () => {
  const env = setup(), failure = new Error('transport stopped'); let count = 0;
  env.connection.request = async () => { if (++count === 2) throw failure; return { status: 'matches', page: {} }; };
  await assert.rejects(collectLogins(env.connection, env.search, env.effects), error => error === failure);
  assert.equal(count, 2); assert.equal(env.stats().accepted, 1); assert.equal(env.stats().freed, 1); assert.equal(env.stats().closed, 1);
});
test('navigation abort before reply acceptance never publishes metadata', async () => {
  const env = setup(), failure = new Error('page changed');
  env.connection.request = async () => { env.controller.abort(failure); return { status: 'matches', page: {} }; };
  await assert.rejects(collectLogins(env.connection, env.search, env.effects), error => error === failure);
  assert.equal(env.stats().accepted, 0); assert.equal(env.stats().freed, 1);
});
test('navigation observer ignores other tabs/frames and detaches all listeners', () => {
  const event = () => { const listeners = new Set(); return { addListener: fn => listeners.add(fn), removeListener: fn => listeners.delete(fn), emit: value => { for (const fn of listeners) fn(value); }, size: () => listeners.size }; };
  const navigations = Array.from({ length: 4 }, event), removed = event(); let changes = 0;
  const chrome = { webNavigation: { onBeforeNavigate: navigations[0], onCommitted: navigations[1], onHistoryStateUpdated: navigations[2], onReferenceFragmentUpdated: navigations[3] }, tabs: { onRemoved: removed } };
  const page = new BrowserPage(chrome, () => {});
  const stop = page.watch({ tabId: 1, frame: { frameId: 2 } }, () => changes++);
  navigations[0].emit({ tabId: 3, frameId: 0 }); navigations[1].emit({ tabId: 1, frameId: 7 }); assert.equal(changes, 0);
  navigations[2].emit({ tabId: 1, frameId: 0 }); assert.equal(changes, 1);
  removed.emit(1); assert.equal(changes, 2);
  stop(); for (const event of [...navigations, removed]) assert.equal(event.size(), 0);
});
