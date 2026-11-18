import init, { create_identity } from './wasm/zann_browser.js';
import { pairedConnection } from './paired.js';
import { loadIdentity } from './identity.js';
import { performAccountCeremony } from './account-ceremony.js';
const $ = id => document.getElementById(id);
let native, prompt, busy = false, cancelled = false;
const abort = new AbortController();
const documentPort = chrome.runtime.connect({ name: 'zann-account-document' });
const close = () => { cancelled = true; abort.abort(); native?.close(); documentPort.disconnect(); };
window.addEventListener('pagehide', close, { once: true });
documentPort.onDisconnect.addListener(close);
const timer = setTimeout(close, 120000);
function failure(reason) { return native.request({ method: 'account_ceremony_finish', operation_id: prompt.options.operation_id, completion: { outcome: 'failed', reason } }); }
$('cancel').addEventListener('click', event => {
  if (!event.isTrusted) return;
  cancelled = true; abort.abort();
  if (!busy && native && prompt) void failure('cancelled').finally(close);
  else close();
});
documentPort.onMessage.addListener(message => {
  if (!message.ready || window.top !== window || location.hash.length !== 37) { close(); return; }
  void (async () => {
    await init();
    native = await pairedConnection(chrome, await loadIdentity(chrome, create_identity, navigator.locks));
    if (cancelled) { close(); return; }
    const status = await native.request({ method: 'account_ceremony_status' });
    if (status.status !== 'account_ceremony_pending' || !status.prompt) throw new Error('No account request is pending.');
    const taken = await native.request({ method: 'account_ceremony_take', operation_id: status.prompt.options.operation_id });
    if (taken.status !== 'account_ceremony_pending' || !taken.prompt) throw new Error('Account request expired.');
    prompt = taken.prompt;
    const labels = { register: 'Add a sign-in key', test: 'Test the new sign-in key', login: 'Sign in to Zann', authorize: 'Confirm a security change' };
    $('title').textContent = labels[prompt.options.phase];
    $('purpose').textContent = prompt.require_prf ? 'Use a PIN or biometrics to sign in and open your personal vault.' : 'Use a PIN or biometrics to confirm this request.';
    $('server').textContent = prompt.server_address; $('rp').textContent = prompt.options.rp_id; $('fingerprint').textContent = prompt.server_fingerprint;
    $('continue').disabled = false;
  })().catch(error => { $('notice').textContent = error.message; native?.close(); });
});
$('continue').addEventListener('click', event => {
  if (!event.isTrusted || busy || !prompt || cancelled) return;
  busy = true; $('continue').disabled = true;
  // Request only this RP host from this trusted user gesture.
  const scheme = prompt.options.rp_id === 'localhost' ? 'http' : 'https';
  const permission = chrome.permissions.request({ origins: [`${scheme}://${prompt.options.rp_id}/*`] });
  void (async () => {
    if (!await permission) throw new Error('Permission for the passkey domain was declined.');
    const result = await performAccountCeremony(prompt, navigator.credentials, abort.signal);
    if (cancelled) { result.prf?.fill(0); return; }
    if (result.missingPrf) {
      await failure('missing_prf');
      $('notice').textContent = 'This key cannot open the vault through PRF. Choose sign-in only explicitly in Zann, or use a PRF-capable key.';
    } else {
      try { await native.accountResponse(prompt.options.operation_id, result.response, result.prf); }
      finally { result.prf.fill(0); }
      $('notice').textContent = 'Confirmed. Continue in the Zann app.';
    }
    clearTimeout(timer); close();
  })().catch(async cause => {
    if (!cancelled) {
      $('notice').textContent = 'The security key request did not complete. Restart it from the Zann app.';
      try { await failure('provider'); } catch (error) { /* terminal transport error; no retry or retained result */ }
    }
    native?.close();
  });
});
