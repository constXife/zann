import { allHttps, siteGrants, sitePattern } from './sites.js';

export async function siteSettings(chrome) {
  const globalButton = document.getElementById('all-sites-toggle');
  const siteButton = document.getElementById('site-toggle');
  const globalStatus = document.getElementById('all-sites-status');
  const siteStatus = document.getElementById('site-status');
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const pattern = tab?.url?.startsWith('https:') ? sitePattern(tab.url) : null;
  if (pattern) document.getElementById('site-host').textContent = new URL(tab.url).hostname;
  else siteStatus.textContent = 'Open an HTTPS website to manage this site.';

  async function update() {
    const { allSuggestions, sites } = await siteGrants(chrome);
    globalButton.dataset.enabled = String(allSuggestions);
    globalButton.textContent = allSuggestions ? 'Turn off all-sites suggestions' : 'Enable on all HTTPS sites';
    globalButton.disabled = false;
    globalStatus.textContent = allSuggestions ? 'Field suggestions are enabled on all HTTPS sites.' : '';
    if (!pattern) return;
    const enabled = sites.includes(pattern);
    siteButton.dataset.enabled = String(enabled);
    siteButton.textContent = allSuggestions
      ? (enabled ? 'Disable passkeys on this site' : 'Enable passkeys on this site')
      : (enabled ? 'Disable on this site' : 'Enable on this site');
    siteButton.disabled = false;
    siteStatus.textContent = allSuggestions ? 'Passkeys are enabled per site.' : 'This setting controls field suggestions and passkeys for this site.';
  }

  function bind(button, origin, status) {
    button.addEventListener('click', async event => {
      if (!event.isTrusted || button.disabled) return;
      button.disabled = true;
      const permission = { origins: [origin] };
      try {
        // Chrome requires the permission request inside the trusted click.
        const granted = button.dataset.enabled === 'true'
          ? await chrome.permissions.remove(permission) : await chrome.permissions.request(permission);
        await update();
        if (!granted) status.textContent = 'Chrome did not change site access.';
      } catch (error) {
        status.textContent = error.message;
        button.disabled = false;
      }
    });
  }
  bind(globalButton, allHttps, globalStatus);
  if (pattern) bind(siteButton, pattern, siteStatus);
  chrome.permissions.onAdded.addListener(update);
  chrome.permissions.onRemoved.addListener(update);
  await update();
}
