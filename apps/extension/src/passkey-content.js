// Isolated bridge. Page messages carry options, never origins or native packets.
export function installPasskeyBridge() {
  if (globalThis.__zannPasskeyBridge) return;
  globalThis.__zannPasskeyBridge = true;
  let active;
  addEventListener('message', event => {
    if (event.source !== window || event.origin !== location.origin) return;
    const message = event.data;
    if (message?.channel === 'zann-passkey-cancel' && active?.id === message.id) { active.port.disconnect(); active = null; return; }
    if (message?.channel !== 'zann-passkey-request' || typeof message.id !== 'string' || message.id.length > 64 || !['create', 'get'].includes(message.kind)) return;
    const fail = () => window.postMessage({ channel: 'zann-passkey-result', id: message.id, error: 'Zann could not complete this passkey request.' }, location.origin);
    if (active || JSON.stringify(message).length > 65536) { fail(); return; }
    const port = chrome.runtime.connect({ name: 'zann-passkey-page' }); active = { id: message.id, port };
    port.onMessage.addListener(result => {
      if (active?.port !== port) return;
      window.postMessage({ channel: 'zann-passkey-result', id: message.id, ...result }, location.origin);
      active = null; port.disconnect();
    });
    port.onDisconnect.addListener(() => { if (active?.port === port) { active = null; fail(); } });
    port.postMessage({ kind: message.kind, options: message.options });
  });
}
