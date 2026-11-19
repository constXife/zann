import { accountWindows } from './account-background.js';
import init, { checked_context, checked_passkey_request, create_identity } from './wasm/zann_browser.js';
import { passkeyBroker } from './passkey-background.js';
import { BrowserPage } from './browser.js';
import { loadIdentity } from './identity.js';
import { InlineSession } from './inline-session.js';
import { siteAccess, syncSites, installInTab } from './sites.js';

const initialized = init();
accountWindows(chrome);
const broker = {
  chrome, pages: new Set(), tokens: new Map(),
  async identity() { await initialized; return loadIdentity(chrome, create_identity, navigator.locks); }
};
passkeyBroker({ ...broker, hasPasskeyAccess: async url => (await siteAccess(chrome, url)).passkeys }, initialized, checked_context, checked_passkey_request);
async function authorize(sender) {
  await initialized;
  if (sender.id !== chrome.runtime.id || !Number.isInteger(sender.tab?.id) || sender.frameId !== 0 || !sender.documentId) throw new Error('Untrusted field document.');
  const page = new BrowserPage(chrome, checked_context, sender.tab.id);
  const target = page.select(await page.frames(), 0);
  // sender.url can retain the committed URL after history.pushState. The stable
  // document ID authenticates the producer; current URL comes from navigation.
  if (target.top.documentId !== sender.documentId || !(await siteAccess(chrome, target.top.url)).suggestions) throw new Error('Site is not enabled.');
  return { page, target };
}
chrome.runtime.onConnect.addListener(port => {
  if (port.name.startsWith('zann-passkey-') || port.name === 'zann-account-document') return;
  if (port.name === 'zann-field') {
    if (broker.pages.size >= 16) { port.disconnect(); return; }
    const ready = authorize(port.sender);
    const session = new InlineSession(broker, port, ready); broker.pages.add(session);
    void ready.catch(() => { session.disable(); broker.pages.delete(session); });
  } else if (port.name.startsWith('zann-picker:')) {
    const session = broker.tokens.get(port.name.slice('zann-picker:'.length));
    if (!session) { port.disconnect(); return; }
    const epoch = session.epoch;
    void session.attach(port).catch(error => {
      if (session.picker === port) session.failed(error, epoch);
      if (epoch === session.epoch) port.postMessage({ type: 'refused', message: error.message });
      port.disconnect();
    });
  } else port.disconnect();
});
function invalidate(details) {
  for (const session of broker.pages) {
    if (session.port.sender.tab?.id === details.tabId && details.frameId === 0) session.disable();
  }
}
chrome.webNavigation.onBeforeNavigate.addListener(invalidate);
for (const event of [chrome.webNavigation.onHistoryStateUpdated, chrome.webNavigation.onReferenceFragmentUpdated]) event.addListener(details => {
  if (details.frameId !== 0) return;
  invalidate(details);
  if (!details.url.startsWith('https:')) return;
  void installInTab(chrome, details.tabId);
});
chrome.tabs.onActivated.addListener(({ tabId }) => {
  for (const session of broker.pages) if (session.port.sender.tab?.id !== tabId) session.hide();
  void installInTab(chrome, tabId);
});
chrome.tabs.onRemoved.addListener(tabId => { for (const session of broker.pages) if (session.port.sender.tab?.id === tabId) { session.reset(); broker.pages.delete(session); } });
chrome.storage.onChanged.addListener((changes, area) => { if (area === 'local' && changes.identity) for (const session of broker.pages) session.hide(); });
chrome.permissions.onRemoved.addListener(() => {
  for (const session of broker.pages) session.hide();
  void (async () => { for (const session of broker.pages) if (!(await siteAccess(chrome, session.port.sender.url)).suggestions) session.disable(); })();
  void syncSites(chrome, navigator.locks);
});
chrome.permissions.onAdded.addListener(() => {
  void (async () => {
    await syncSites(chrome, navigator.locks);
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (Number.isInteger(tab?.id)) await installInTab(chrome, tab.id);
  })();
});
// Permission events outlive the toolbar popup/Chrome consent sheet. Chrome
// retains registrations across restarts; no second grant database.
chrome.runtime.onStartup.addListener(() => { void syncSites(chrome, navigator.locks); });
chrome.runtime.onInstalled.addListener(() => { void syncSites(chrome, navigator.locks); });
