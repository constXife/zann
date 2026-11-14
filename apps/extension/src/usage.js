// Chrome storage/locking adapter only. Rust owns the record schema, scope,
// bounded retention, match priority and stable MRU ordering for both surfaces.
import { NativeBrowserUsage } from './wasm/zann_browser.js';
import { AUTOFILL_USAGE_KEY, withIdentity } from './identity.js';

export class UsageError extends Error {}
export class UsageWriteError extends UsageError {}

async function model(chrome) {
  const snapshot = (await chrome.storage.local.get(AUTOFILL_USAGE_KEY))[AUTOFILL_USAGE_KEY];
  if (snapshot !== undefined && typeof snapshot !== 'string') throw new Error('Invalid local autofill history.');
  return new NativeBrowserUsage(snapshot === undefined ? 'null' : snapshot);
}
export async function rankLogins(chrome, identity, locks, result) {
  try {
    return await withIdentity(chrome, identity, locks, async () => {
      const usage = await model(chrome);
      try { return JSON.parse(usage.rank(identity.server, JSON.stringify(result))); }
      finally { usage.free(); }
    });
  } catch (cause) {
    throw new UsageError('Local autofill history is unavailable. Forget this browser connection in Settings to reset it.', { cause });
  }
}
export async function fillAndRemember(chrome, identity, locks, scope, itemId, insert) {
  // This callback must resolve only after checked isolated-world insertion.
  // Querying, requesting a secret or a failed/ambiguous insertion grants no MRU.
  await insert();
  try {
    await withIdentity(chrome, identity, locks, async () => {
      const usage = await model(chrome);
      try {
        usage.record_success(identity.server, JSON.stringify(scope), itemId);
        await chrome.storage.local.set({ [AUTOFILL_USAGE_KEY]: usage.snapshot() });
      } finally { usage.free(); }
    });
  } catch (cause) {
    // Insertion already succeeded. Never report this as a failed fill/replay it.
    throw new UsageWriteError('Fields filled. Local autofill history could not be saved.', { cause });
  }
}
