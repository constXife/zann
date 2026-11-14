import { sitePattern, hasSite } from './sites.js';
export async function siteSettings(chrome) {
  const button = document.getElementById('site-toggle'), label = document.getElementById('site-host'), status = document.getElementById('site-status');
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url?.startsWith('https:')) { status.textContent = 'Suggestions are available on HTTPS websites.'; return; }
  const pattern = sitePattern(tab.url);
  label.textContent = `${new URL(tab.url).hostname} · HTTPS, all ports`;
  async function update() {
    const enabled = await hasSite(chrome, tab.url);
    button.textContent = enabled ? 'Disable on this site' : 'Enable on this site';
    button.dataset.enabled = String(enabled); button.disabled = false;
    status.textContent = enabled ? 'Focus a login field to see Zann suggestions.' : 'Allow access to this website to show suggestions beside fields.';
  }
  button.addEventListener('click', event => {
    if (!event.isTrusted || button.disabled) return;
    button.disabled = true;
    // Invoke request directly in the actual click stack, before any await.
    const enabled = button.dataset.enabled === 'true';
    const permission = enabled ? chrome.permissions.remove({ origins: [pattern] }) : chrome.permissions.request({ origins: [pattern] });
    void (async () => {
      try {
        const granted = await permission;
        await update();
        if (!enabled && !granted) status.textContent = 'Permission was declined. Suggestions remain disabled.';
      } catch (error) { status.textContent = error.message; button.disabled = false; }
    })();
  });
  await update();
}
