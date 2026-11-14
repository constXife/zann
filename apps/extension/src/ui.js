import { VirtualLoginList } from './login-list.js';
import { NativeLoginList } from './wasm/zann_browser.js';
export const $ = id => document.getElementById(id);
export function notice(message, error = false) {
  $('notice').textContent = message;
  $('notice').hidden = !message;
  $('notice').toggleAttribute('data-error', error);
}
export function options(id, values) {
  $(id).replaceChildren(...values.map(([value, label]) => {
    const option = document.createElement('option'); option.value = value; option.textContent = label; return option;
  }));
  $(id).disabled = !values.length;
}
export const loginList = new VirtualLoginList({
  root: $('matches'), search: $('login-search'), input: $('login-filter'), count: $('login-count'), empty: $('login-empty'), maxHeight: 240,
  messages: { empty: 'No matching logins for this website.', noResults: 'No logins match your search.', count: (found, total) => found === total ? `${total} logins` : `${found} of ${total} logins` },
  onError: error => notice(error.message, true)
});
export function matches(items, onFill) {
  loginList.setModel(new NativeLoginList(JSON.stringify(items)), onFill);
}
export function clearMatches() { loginList.clear(); }
export function discard() { $('save-login').reset(); $('save-login').hidden = true; }
