// Only the pairing seed and PAKE-authenticated server pin persist locally.
const lockName = 'zann-pairing-identity-v1';
export const AUTOFILL_USAGE_KEY = 'autofillUsage';
function validate(identity) {
  if (identity?.version !== 1 || !/^[0-9a-f]{64}$/.test(identity.seed) ||
      !(identity.server === null || /^[0-9a-f]{64}$/.test(identity.server))) {
    throw new Error('Invalid pairing storage. Forget this connection explicitly.');
  }
  return identity;
}
async function restricted(chrome) {
  await chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
}
function unchanged(current, expected) {
  validate(current);
  if (current.seed !== expected.seed || current.server !== expected.server) {
    throw new Error('Connection changed in another popup. Reopen this popup.');
  }
}
export async function loadIdentity(chrome, createIdentity, locks) {
  await restricted(chrome);
  return locks.request(lockName, async () => {
    const { identity } = await chrome.storage.local.get('identity');
    if (identity !== undefined) return validate(identity);
    const fresh = { version: 1, seed: createIdentity(), server: null };
    validate(fresh); await chrome.storage.local.set({ identity: fresh });
    return fresh;
  });
}
export async function pinIdentity(chrome, expected, server, locks) {
  return locks.request(lockName, async () => {
    const { identity } = await chrome.storage.local.get('identity');
    unchanged(identity, expected);
    if (identity.server !== null) throw new Error('Forget the existing connection before pairing again.');
    const pinned = validate({ ...identity, server });
    await chrome.storage.local.set({ identity: pinned });
    return pinned;
  });
}
// Serialize ancillary local metadata with pairing/Forget. A late successful
// fill from an old identity must not recreate history after an explicit reset.
export function withIdentity(chrome, expected, locks, operation) {
  return locks.request(lockName, async () => {
    const { identity } = await chrome.storage.local.get('identity');
    unchanged(identity, expected);
    if (identity.server === null) throw new Error('Connect this browser before using local autofill history.');
    return operation();
  });
}
export async function forgetIdentity(chrome, expected, createIdentity, locks) {
  await restricted(chrome);
  return locks.request(lockName, async () => {
    const { identity } = await chrome.storage.local.get('identity');
    if (expected) unchanged(identity, expected);
    // One atomic storage.set replaces the old identity. No remove/create gap.
    // Explicit Forget also permits recovery of an invalid snapshot.
    const fresh = validate({ version: 1, seed: createIdentity(), server: null });
    // Clear metadata first. A crash here leaves the old identity with no
    // history; the identity itself still changes in one atomic storage write.
    await chrome.storage.local.remove(AUTOFILL_USAGE_KEY);
    await chrome.storage.local.set({ identity: fresh });
    return fresh;
  });
}
