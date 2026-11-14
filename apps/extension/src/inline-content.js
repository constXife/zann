// Built as a classic isolated-world script alongside the shared bounded adapter.
export function installInline(fields, keyIcon) {
  const installed = '__zannInlineController';
  const hostId = `zann-inline-${chrome.runtime.id}`;
  if (globalThis[installed]?.url === location.href && globalThis[installed].hostId === hostId && globalThis[installed].valid()) return;
  globalThis[installed]?.();
  document.getElementById(hostId)?.remove();
  let pagePort, host, root, icon, picker, anchor, selection, request = 0, raf, observed, open = false, pickerHeight = 72;
  const topURL = location.href;
  const command = operation => ({ operation, namespace: 'inline', topURL, frameURL: topURL });
  function position() {
    raf = null;
    if (!anchor?.isConnected || !anchor.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true }) || location.href !== topURL) { close(); return; }
    const r = anchor.getBoundingClientRect();
    if (r.width < 44 || r.height < 20 || r.bottom < 0 || r.top > innerHeight) { close(); return; }
    icon.style.cssText = `position:fixed;left:${Math.max(r.left, r.right - 28)}px;top:${r.top + Math.max(0, (r.height - 24) / 2)}px;width:24px;height:24px;padding:4px;display:grid;place-items:center;pointer-events:auto;border:0;border-radius:5px;background:transparent;color:light-dark(#007aff,#71b1ff);`;
    if (picker) {
      const width = Math.min(320, innerWidth - 16), height = Math.min(pickerHeight, innerHeight - 16);
      const above = r.top >= height + 8;
      const y = above ? r.top - height - 8 : r.bottom + height + 8 <= innerHeight ? r.bottom + 8 : Math.max(8, innerHeight - height - 8);
      picker.style.cssText = `position:fixed;left:${Math.max(8, Math.min(r.left, innerWidth - width - 8))}px;top:${y}px;width:${width}px;height:${height}px;pointer-events:auto;border:0;border-radius:12px;box-shadow:0 8px 30px #0003;color-scheme:light dark;`;
    }
  }
  function schedule() { if (!raf) raf = requestAnimationFrame(position); }
  function close() {
    request++; open = false; picker?.remove(); picker = null; observed?.disconnect(); observed = null;
    icon?.setAttribute('aria-expanded', 'false');
    pagePort?.postMessage({ type: 'close' });
  }
  function mount() {
    if (host) return;
    host = document.createElement('div');
    host.id = hostId;
    host.style.cssText = 'all:initial!important;position:fixed!important;left:0!important;top:0!important;width:0!important;height:0!important;z-index:2147483647!important;pointer-events:none!important;color-scheme:light dark!important;';
    root = host.attachShadow({ mode: 'closed' });
    icon = document.createElement('button'); icon.type = 'button'; icon.append(keyIcon(document));
    icon.setAttribute('aria-label', 'Zann — подходящие логины'); icon.setAttribute('aria-expanded', 'false');
    icon.addEventListener('mousedown', e => { if (e.isTrusted) e.preventDefault(); });
    icon.addEventListener('click', e => { if (e.isTrusted) { if (open) close(); else show(); } });
    root.append(icon); document.documentElement.append(host);
  }
  function connect() {
    if (pagePort) return true;
    try { pagePort = chrome.runtime.connect({ name: 'zann-field' }); }
    catch (error) {
      if (error.message !== 'Extension context invalidated.') throw error;
      // Chrome revoked this script instance on extension reload. Remove its
      // owned UI/listeners; a new packaged instance owns future interactions.
      destroy(); return false;
    }
    pagePort.onDisconnect.addListener(() => { pagePort = null; close(); host?.remove(); host = null; anchor = null; });
    pagePort.onMessage.addListener(message => {
      if (message.type === 'disabled') { destroy(); return; }
      if (message.type === 'hide') { close(); return; }
      if (message.type === 'resize' && message.request === request && Number.isInteger(message.height) && message.height >= 56 && message.height <= 320) { pickerHeight = message.height; schedule(); return; }
      if (message.type !== 'mount' || message.request !== request || !open || !anchor?.isConnected) return;
      picker?.remove(); picker = document.createElement('iframe'); picker.src = message.url;
      picker.title = 'Zann — подсказки автозаполнения'; picker.referrerPolicy = 'no-referrer';
      root.append(picker); icon.setAttribute('aria-expanded', 'true'); position();
    });
    return true;
  }
  function show() {
    const scan = fields(command('scan'));
    if (!scan.ok) return;
    const found = fields({ ...command('locate'), token: scan.token, field: anchor });
    if (!found.ok) return;
    selection = { token: scan.token, form: found.form };
    if (!connect()) return;
    open = true; request++; pickerHeight = 72;
    pagePort.postMessage({ type: 'open', request, ...selection });
    observed?.disconnect(); observed = new MutationObserver(() => { if (!anchor?.isConnected) close(); });
    observed.observe(document, { subtree: true, childList: true });
  }
  function focus(event) {
    if (!event.isTrusted || document.visibilityState !== 'visible') return;
    const field = event.composedPath()[0];
    if (!(field instanceof HTMLInputElement)) return;
    if (anchor === field && open) return;
    close(); anchor = field;
    const scan = fields(command('scan'));
    if (!scan.ok || !fields({ ...command('locate'), token: scan.token, field }).ok) { host?.remove(); host = null; return; }
    mount(); position(); show();
  }
  function outside(event) { if (event.isTrusted && !event.composedPath().includes(host) && event.composedPath()[0] !== anchor) close(); }
  function key(event) {
    if (!event.isTrusted || event.isComposing || !open) return;
    if (event.key === 'Escape') { event.preventDefault(); close(); }
    if (['ArrowDown', 'ArrowUp', 'Enter'].includes(event.key) && event.composedPath()[0] === anchor) {
      event.preventDefault(); pagePort?.postMessage({ type: 'key', key: event.key });
    }
  }
  function hidden() { if (document.visibilityState !== 'visible') close(); }
  function navigated() { close(); host?.remove(); host = null; anchor = null; }
  function destroy() {
    close(); pagePort?.disconnect(); pagePort = null; host?.remove(); host = null;
    document.removeEventListener('focusin', focus, true); document.removeEventListener('pointerdown', outside, true);
    document.removeEventListener('keydown', key, true); document.removeEventListener('visibilitychange', hidden);
    window.removeEventListener('scroll', schedule, true); window.removeEventListener('resize', schedule);
    window.removeEventListener('pagehide', destroy); window.removeEventListener('popstate', navigated); window.removeEventListener('hashchange', navigated);
    if (raf) cancelAnimationFrame(raf); delete globalThis[installed];
  }
  document.addEventListener('focusin', focus, true); document.addEventListener('pointerdown', outside, true); document.addEventListener('keydown', key, true);
  document.addEventListener('visibilitychange', hidden); window.addEventListener('scroll', schedule, true); window.addEventListener('resize', schedule);
  window.addEventListener('pagehide', destroy); window.addEventListener('popstate', navigated); window.addEventListener('hashchange', navigated);
  globalThis[installed] = destroy;
  destroy.url = topURL; destroy.hostId = hostId; destroy.valid = () => Boolean(chrome.runtime.id);
  // No synthetic focus and no page-load fill/query. A real field focus starts UI.
}
