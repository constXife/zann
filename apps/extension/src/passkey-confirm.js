const token = location.hash.slice(1);
const port = chrome.runtime.connect({ name: `zann-passkey-confirm:${token}` });
const choices = document.querySelector('#choices');
let confirmed = false;
function confirm(event, item_id) {
  if (!event.isTrusted || confirmed) return;
  confirmed = true;
  for (const button of choices.querySelectorAll('button')) button.disabled = true;
  port.postMessage({ type: 'confirm', item_id });
}
port.onMessage.addListener(message => {
  document.querySelector('#heading').textContent = message.kind === 'create' ? 'Create a passkey' : 'Sign in with a passkey';
  document.querySelector('#rp').textContent = message.rp;
  document.querySelector('#account').textContent = message.kind === 'create' ? message.user : '';
  choices.replaceChildren();
  if (message.kind === 'create') {
    const button = document.createElement('button'); button.textContent = 'Create passkey';
    button.addEventListener('click', event => confirm(event)); choices.append(button);
  } else for (const item of message.items) {
    const button = document.createElement('button'); button.textContent = item.user_display_name || item.user_name || item.title;
    button.addEventListener('click', event => confirm(event, item.item_id)); choices.append(button);
  }
});
port.onDisconnect.addListener(() => { document.querySelector('#error').textContent = 'This passkey request ended. Close this window and try again.'; });
document.querySelector('#cancel').addEventListener('click', event => { if (event.isTrusted) port.postMessage({ type: 'cancel' }); });
