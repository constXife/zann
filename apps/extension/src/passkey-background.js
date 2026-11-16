import { BrowserPage } from './browser.js';
import { pairedConnection } from './paired.js';

// Confirmation lives in an extension-only top-level window, never an embeddable
// page-controlled overlay. Each window consumes one native ticket exactly once.
export function passkeyBroker(broker, initialized, checkedContext, checkedRequest) {
  const sessions = new Map();
  const chooserURL = chrome.runtime.getURL('passkey.html');
  chrome.runtime.onConnect.addListener(port => {
    if (port.name === 'zann-passkey-page') {
      if (sessions.size >= 8) { port.disconnect(); return; }
      const token = crypto.randomUUID();
      const session = { port, done: false, confirming: false, token }; sessions.set(token, session);
      const close = () => {
        if (session.done) return;
        session.done = true; clearTimeout(session.timer); session.unwatch?.(); session.native?.close(); sessions.delete(token);
        session.chooser?.disconnect(); port.disconnect();
        if (session.windowId !== undefined) void chrome.windows.remove(session.windowId).catch(error => { if (!String(error.message).includes('No window')) throw error; });
      };
      session.close = close;
      session.fail = cause => {
        // Only causal diagnostics: never request/options, packets or metadata.
        if (cause instanceof Error) console.debug(new Error('Zann passkey ceremony failed.', { cause }));
        if (!session.done) port.postMessage({ error: 'Zann refused this passkey request. Unlock Zann and try again.' }); close(); };
      session.timer = setTimeout(session.fail, 30000);
      port.onDisconnect.addListener(close);
      let received = false;
      port.onMessage.addListener(message => {
        if (received) { session.fail(); return; } received = true;
        void (async () => {
          await initialized;
          const sender = port.sender;
          if (sender.id !== chrome.runtime.id || !sender.documentId || !Number.isInteger(sender.tab?.id) || !Number.isInteger(sender.frameId)) throw new Error('Untrusted passkey document.');
          const page = new BrowserPage(chrome, checkedContext, sender.tab.id);
          const snapshot = await page.frames(), target = page.select(snapshot, sender.frameId);
          if (target.frame.documentId !== sender.documentId || !await broker.hasSite(target.top.url)) throw new Error('Site is not enabled.');
          // Every ancestor must be same-origin; top == requester alone is
          // insufficient when a hostile intermediate frame embeds this site.
          let ancestor = target.frame;
          for (let depth = 0; ancestor.frameId !== 0; depth++) {
            if (depth >= 16) throw new Error('Frame ancestry limit.');
            ancestor = snapshot.frames.find(frame => frame.frameId === ancestor.parentFrameId);
            if (!ancestor) throw new Error('Frame ancestry unavailable.');
            checkedContext(snapshot.top.url, ancestor.url);
          }
          session.request = JSON.parse(checkedRequest(target.top.url, target.frame.url, message.kind, JSON.stringify(message.options)));
          session.page = page; session.target = target;
          session.unwatch = page.watch(target, session.fail);
          const native = await pairedConnection(chrome, await broker.identity());
          if (session.done) { native.close(); return; } session.native = native;
          const reply = await native.request({ method: 'passkey_query', request: session.request });
          if (session.done) return;
          if (reply.status !== 'passkey_matches' || (message.kind === 'get' && !reply.matches.items.length)) throw new Error('No passkey available.');
          session.ticket = reply.ticket; session.matches = reply.matches; session.kind = message.kind;
          await page.assertCurrent(target);
          const window = await chrome.windows.create({ url: `${chooserURL}#${token}`, type: 'popup', width: 440, height: 520, focused: true });
          session.windowId = window.id;
          if (session.done) await chrome.windows.remove(window.id);
        })().catch(session.fail);
      });
    } else if (port.name.startsWith('zann-passkey-confirm:')) {
      const token = port.name.slice('zann-passkey-confirm:'.length), session = sessions.get(token);
      if (!session || session.chooser || port.sender.id !== chrome.runtime.id || port.sender.url !== `${chooserURL}#${token}`) { port.disconnect(); return; }
      session.chooser = port;
      port.onDisconnect.addListener(session.close);
      port.postMessage({ kind: session.kind, rp: session.request.rp_id, user: session.request.operation?.user_name,
        items: session.matches.items });
      port.onMessage.addListener(message => {
        if (message.type === 'cancel') { session.fail(); return; }
        if (message.type !== 'confirm' || session.confirming || session.done) return;
        session.confirming = true;
        void (async () => {
          await session.page.assertCurrent(session.target);
          if (!await broker.hasSite(session.target.top.url)) throw new Error('Site permission was removed.');
          if (session.done) return;
          const request = session.kind === 'create' ? { method: 'make_credential', ticket: session.ticket, gesture: true }
            : { method: 'get_assertion', ticket: session.ticket, item_id: message.item_id, gesture: true };
          const reply = await session.native.request(request);
          if (session.done) return;
          await session.page.assertCurrent(session.target);
          if (reply.status !== 'credential') throw new Error('Unexpected passkey result.');
          session.port.postMessage({ response: reply.response }); session.close();
        })().catch(session.fail);
      });
    }
  });
  chrome.permissions.onRemoved.addListener(() => { for (const session of sessions.values()) session.fail(); });
  chrome.storage.onChanged.addListener((changes, area) => { if (area === 'local' && changes.identity) for (const session of sessions.values()) session.fail(); });
  chrome.windows.onRemoved.addListener(id => { for (const session of sessions.values()) if (session.windowId === id) session.fail(); });
}
