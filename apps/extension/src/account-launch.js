import { pairedConnection } from './paired.js';
export async function showPendingAccount(chrome, identity, section, label, button) {
  if (!identity?.server) return;
  const native = await pairedConnection(chrome, identity);
  try {
    const reply = await native.request({ method: 'account_ceremony_status' });
    if (reply.status !== 'account_ceremony_pending') throw new Error('Unexpected account status.');
    if (!reply.prompt) return;
    label.textContent = `Continue the request from Zann for ${reply.prompt.options.rp_name}.`;
    section.hidden = false;
    button.addEventListener('click', event => {
      if (!event.isTrusted) return;
      button.disabled = true;
      void chrome.runtime.sendMessage({ type: 'zann-account-open' }).then(reply => {
        if (!reply?.accepted) { label.textContent = 'Could not open confirmation. Reopen the toolbar to try again.'; button.disabled = false; }
        else window.close();
      });
    }, { once: true });
  } finally { native.close(); }
}
