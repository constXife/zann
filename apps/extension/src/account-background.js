// The private account window is never web accessible. Only an extension popup
// can open it, and the exact top-level document/window consumes its capability.
export function accountWindows(chrome) {
  let active;
  const page = chrome.runtime.getURL('account-access.html');
  const remove = id => chrome.windows.remove(id).catch(error => {
    if (!String(error.message).includes('No window')) throw error;
  });
  chrome.runtime.onMessage.addListener((message, sender, respond) => {
    if (message?.type !== 'zann-account-open') return;
    if (sender.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL('popup.html')
      || (sender.tab && sender.frameId !== 0)) { respond({ accepted: false }); return; }
    void (async () => {
      if (active) { await active.ready; await chrome.windows.update(active.windowId, { focused: true }); return; }
      const entry = { token: crypto.randomUUID(), documentId: null };
      active = entry;
      entry.ready = chrome.windows.create({ url: `${page}#${entry.token}`, type: 'popup', width: 480, height: 540, focused: true }).then(window => {
        if (!Number.isInteger(window.id) || window.tabs?.length !== 1) throw new Error('Account window unavailable.');
        entry.windowId = window.id; entry.tabId = window.tabs[0].id;
      });
      await entry.ready;
    })().then(() => respond({ accepted: true }), error => {
      active = null; respond({ accepted: false });
      console.debug(new Error('Could not open account confirmation.', { cause: error }));
    });
    return true;
  });
  chrome.runtime.onConnect.addListener(port => {
    if (port.name !== 'zann-account-document') return;
    const entry = active, sender = port.sender;
    if (!entry || sender.id !== chrome.runtime.id || sender.url !== `${page}#${entry.token}` || sender.frameId !== 0
      || !sender.documentId || entry.documentId) { port.disconnect(); return; }
    let closed = false;
    port.onDisconnect.addListener(() => {
      closed = true;
      if (active === entry && entry.documentId === sender.documentId) { active = null; void remove(entry.windowId); }
    });
    void (async () => {
      await entry.ready;
      if (closed || active !== entry || sender.tab?.id !== entry.tabId || sender.tab?.windowId !== entry.windowId) { port.disconnect(); return; }
      entry.documentId = sender.documentId; entry.port = port;
      port.onMessage.addListener(() => port.disconnect());
      port.postMessage({ ready: true });
    })().catch(error => { port.disconnect(); console.debug(new Error('Account document refused.', { cause: error })); });
  });
  chrome.windows.onRemoved.addListener(id => { if (active?.windowId === id) active = null; });
  chrome.permissions.onRemoved.addListener(() => active?.port?.disconnect());
  chrome.storage.onChanged.addListener((changes, area) => { if (area === 'local' && changes.identity) active?.port?.disconnect(); });
}
