import { keyIcon } from './key-icon.js';
import init, { NativeLoginList } from './wasm/zann_browser.js';
import { VirtualLoginList } from './login-list.js';
await init();
const $ = id => document.getElementById(id);
$('brand').prepend(keyIcon(document));
let port, busy = true, refused, kind;
const loginList = new VirtualLoginList({
  root: $('items'), search: $('login-search'), input: $('login-filter'), count: $('login-count'), empty: $('login-empty'), maxHeight: 192,
  messages: { empty: 'Для этого сайта нет сохранённых логинов.', noResults: 'Нет логинов по этому запросу.', count: (found, total) => found === total ? `Логинов: ${total}` : `${found} из ${total}` },
  onError: error => { $('status').textContent = error.message; reportSize(); }
});
function send(message) { port?.postMessage(message); }
function reportSize() { send({ type: 'size', height: Math.max(56, Math.min(320, Math.ceil(document.body.getBoundingClientRect().height))) }); }
function buttons(disabled) {
  busy = disabled; loginList.setDisabled(disabled);
  for (const id of ['retry', 'generate', 'use-generated']) $(id).disabled = disabled;
}
function clear() { loginList.clear(); for (const id of ['retry', 'generate', 'use-generated']) $(id).hidden = true; }
function fill(item) { if (busy) return; buttons(true); send({ type: 'fill', item_id: item.item_id }); }
function key(value) {
  if (value === 'Escape') { send({ type: 'close' }); return; }
  if (!busy) loginList.key(value);
}
function receive(message) {
  if (message.type === 'identify') { send({ type: 'ancestry', origins: Array.from(location.ancestorOrigins) }); return; }
  if (message.type === 'refused') { refused = message.message; return; }
  if (message.type === 'key') { key(message.key); return; }
  if (message.type === 'context') { kind = message.kind; $('host').textContent = message.host; $('mode').hidden = kind !== 'otp'; }
  if (message.type === 'new-password') { clear(); $('status').textContent = 'Надёжный пароль для нового аккаунта'; $('generate').hidden = false; buttons(false); }
  if (message.type === 'loading') { clear(); $('status').textContent = 'Ищем все подходящие логины…'; buttons(true); }
  if (message.type === 'matches') {
    clear(); $('status').textContent = '';
    loginList.setModel(new NativeLoginList(JSON.stringify(message.items)), fill);
    buttons(false);
  }
  if (message.type === 'error') { clear(); $('status').textContent = message.code === 'locked' ? 'Разблокируйте хранилище в приложении Zann.' : message.message; $('retry').hidden = false; buttons(false); }
  if (message.type === 'generated') { clear(); $('status').textContent = `Новый надёжный пароль · ${message.length} символа. Сохраните логин отдельно после заполнения.`; $('use-generated').hidden = false; buttons(false); }
  reportSize();
}
for (const [id, type] of [['close', 'close'], ['retry', 'retry'], ['generate', 'generate'], ['use-generated', 'use-generated']]) $(id).addEventListener('click', event => {
  if (!event.isTrusted || (busy && id !== 'close')) return;
  if (id !== 'close') buttons(true); send({ type });
});
document.addEventListener('keydown', event => {
  if (event.isComposing || !event.isTrusted || event.defaultPrevented || !['ArrowDown', 'ArrowUp', 'Escape', 'Enter', 'Home', 'End', 'PageUp', 'PageDown'].includes(event.key)) return;
  if (event.target instanceof HTMLInputElement && ['Home', 'End'].includes(event.key)) return;
  // Native button Enter already produces the correct trusted click.
  if (event.key === 'Enter' && event.target instanceof HTMLButtonElement) return;
  event.preventDefault(); key(event.key);
});
if (window.top === window || !/^[0-9a-f-]{36}$/.test(location.hash.slice(1))) {
  clear(); $('status').textContent = 'Откройте подсказки из поля входа на разрешённом сайте.'; buttons(true);
} else {
  port = chrome.runtime.connect({ name: `zann-picker:${location.hash.slice(1)}` });
  port.onMessage.addListener(receive);
  port.onDisconnect.addListener(() => { port = null; clear(); $('status').textContent = refused ?? 'Подсказка закрыта. Вернитесь к полю, чтобы открыть её снова.'; buttons(true); });
}
window.addEventListener('pagehide', () => { port?.disconnect(); port = null; clear(); });
new ResizeObserver(reportSize).observe(document.body);
