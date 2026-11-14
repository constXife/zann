// Chrome is the only persistent owner of site grants and registered scripts.
const scriptId = 'zann-inline-sites';
export function sitePattern(url) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' || !parsed.hostname) throw new Error('Inline suggestions require an HTTPS website.');
  // Chrome match patterns scope by host, not port. No subdomain wildcard.
  return `https://${parsed.hostname}/*`;
}
export async function grantedSites(chrome) {
  const { origins = [] } = await chrome.permissions.getAll();
  return origins.filter(origin => /^https:\/\/[^/*]+\/\*$/.test(origin));
}
export async function hasSite(chrome, url) { return (await grantedSites(chrome)).includes(sitePattern(url)); }
export async function syncSites(chrome, locks) {
  return locks.request('zann-inline-sites', async () => {
    const matches = await grantedSites(chrome);
    const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [scriptId] });
    if (!matches.length) {
      if (existing.length) await chrome.scripting.unregisterContentScripts({ ids: [scriptId] });
    } else {
      const script = { id: scriptId, matches, js: ['content.js'], allFrames: false, runAt: 'document_idle', persistAcrossSessions: true, world: 'ISOLATED' };
      if (existing.length) await chrome.scripting.updateContentScripts([script]);
      else await chrome.scripting.registerContentScripts([script]);
    }
  });
}
export async function installInTab(chrome, tabId) {
  const frame = await chrome.webNavigation.getFrame({ tabId, frameId: 0 });
  if (!frame?.documentId || !await hasSite(chrome, frame.url)) throw new Error('Site permission is unavailable.');
  await chrome.scripting.executeScript({ target: { tabId, documentIds: [frame.documentId] }, files: ['content.js'], world: 'ISOLATED' });
}
