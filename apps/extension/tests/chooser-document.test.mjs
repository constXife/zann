import test from 'node:test';
import assert from 'node:assert/strict';
import { identifyChooser } from '../src/chooser-document.js';
function port(origins) {
  const listeners = new Set(), disconnect = new Set();
  return { onMessage: { addListener: fn => listeners.add(fn), removeListener: fn => listeners.delete(fn) },
    onDisconnect: { addListener: fn => disconnect.add(fn), removeListener: fn => disconnect.delete(fn) },
    postMessage: () => queueMicrotask(() => { for (const listener of listeners) listener({ type: 'ancestry', origins }); }),
    listeners, disconnect };
}
test('chooser requires exactly its browser-reported top ancestor and removes handshake listeners', async () => {
  const good = port(['https://example.test']); await identifyChooser(good, 'https://example.test');
  assert.equal(good.listeners.size, 0); assert.equal(good.disconnect.size, 0);
  for (const origins of [[], ['https://evil.test'], ['https://example.test', 'https://example.test'], null]) {
    const bad = port(origins); await assert.rejects(identifyChooser(bad, 'https://example.test'), /parent changed/);
    assert.equal(bad.listeners.size, 0); assert.equal(bad.disconnect.size, 0);
  }
});
