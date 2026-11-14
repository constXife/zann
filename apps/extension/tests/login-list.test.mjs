import test from 'node:test';
import assert from 'node:assert/strict';
import { visibleWindow } from '../src/login-list.js';

test('virtual windows stay bounded at the start, middle and end of an 8192-login list', () => {
  for (const scroll of [-100, 0, 48, 7000 * 48, 8192 * 48, 10000000]) {
    const { start, end } = visibleWindow(8192, scroll, 240, 48, 2);
    assert.ok(start >= 0 && end <= 8192 && start <= end);
    assert.ok(end - start <= 9, 'at most five viewport rows plus two on either side');
  }
  assert.deepEqual(visibleWindow(8192, 7000 * 48, 240, 48, 2), { start: 6998, end: 7007 });
  assert.deepEqual(visibleWindow(8192, 8192 * 48, 240, 48, 2), { start: 8185, end: 8192 });
});

test('empty and shorter-than-viewport lists have no phantom rows', () => {
  assert.deepEqual(visibleWindow(0, 0, 0, 48, 2), { start: 0, end: 0 });
  assert.deepEqual(visibleWindow(2, 999, 96, 48, 2), { start: 0, end: 2 });
});
