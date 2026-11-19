// Chrome owns the optional host grants and persistent registrations.
export const allHttps = 'https://*/*';
const inlineScript = { id: 'zann-inline-sites', js: ['content.js'], allFrames: false, runAt: 'document_idle', world: 'ISOLATED' };
const passkeyScripts = [
  { id: 'zann-passkey-bridge', js: ['passkey-isolated-content.js'], allFrames: true, runAt: 'document_start', world: 'ISOLATED' },
  { id: 'zann-passkey-main', js: ['passkey-main-content.js'], allFrames: true, runAt: 'document_start', world: 'MAIN' }
];

export function sitePattern(url) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' || !parsed.hostname) throw new Error('Inline suggestions require an HTTPS website.');
  return `https://${parsed.hostname}/*`;
}

export async function siteGrants(chrome) {
  const { origins = [] } = await chrome.permissions.getAll();
  return { allSuggestions: origins.includes(allHttps), sites: origins.filter(origin => /^https:\/\/[^/*]+\/\*$/.test(origin)) };
}

export async function siteAccess(chrome, url) {
  if (!url?.startsWith('https:')) return { suggestions: false, passkeys: false };
  const { allSuggestions, sites } = await siteGrants(chrome);
  const passkeys = sites.includes(sitePattern(url));
  return { suggestions: allSuggestions || passkeys, passkeys };
}

export async function syncSites(chrome, locks) {
  return locks.request('zann-inline-sites', async () => {
    const { allSuggestions, sites } = await siteGrants(chrome);
    const scripts = [inlineScript, ...passkeyScripts];
    const registered = await chrome.scripting.getRegisteredContentScripts({ ids: scripts.map(script => script.id) });
    for (const script of scripts) {
      const matches = script === inlineScript && allSuggestions ? [allHttps] : sites;
      const exists = registered.some(existing => existing.id === script.id);
      if (!matches.length) {
        if (exists) await chrome.scripting.unregisterContentScripts({ ids: [script.id] });
        continue;
      }
      const registration = { ...script, matches, persistAcrossSessions: true };
      if (exists) await chrome.scripting.updateContentScripts([registration]);
      else await chrome.scripting.registerContentScripts([registration]);
    }
  });
}

export async function installInTab(chrome, tabId) {
  const frame = await chrome.webNavigation.getFrame({ tabId, frameId: 0 });
  if (!frame?.documentId) return;
  const access = await siteAccess(chrome, frame.url);
  if (!access.suggestions) return;
  const target = { tabId, documentIds: [frame.documentId] };
  // Existing documents need the isolated bridge ready before the page shim.
  const scripts = access.passkeys ? [...passkeyScripts, inlineScript] : [inlineScript];
  for (const { js: files, world } of scripts) await chrome.scripting.executeScript({ target, files, world });
}
