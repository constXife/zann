import init, { NativePairing, NativeLoginSearch, create_identity, checked_context, generate_password } from './wasm/zann_browser.js';
import { collectLogins } from './search.js';
import { NativeConnection } from './native.js';
import { BrowserPage, PageError } from './browser.js';
import * as view from './popup-view.js';
import { loadIdentity, pinIdentity, forgetIdentity } from './identity.js';
import { $, notice, options, matches, clearMatches, discard } from './ui.js';
import { pairedConnection as openPaired } from './paired.js';
import { siteSettings } from './site-settings.js';
import { rankLogins, fillAndRemember, UsageError, UsageWriteError } from './usage.js';

let identity, native, page, snapshot, target, scan, scope, stopWatching, searchAbort, busy = false;
function close() { native?.close(); native = null; }
function clearPage() {
  searchAbort?.abort(new PageError('Page changed. Refresh before continuing.')); searchAbort = null;
  stopWatching?.(); stopWatching = null; target = null; scan = null; scope = null;
  $('workspace').hidden = true; $('page-issue').hidden = true;
  options('form', []); clearMatches(); discard(); $('generated').value = ''; $('use-generated').disabled = true;
}
async function action(task) {
  if (busy) return;
  busy = true; $('controls').disabled = true; $('settings-toggle').disabled = true; document.body.setAttribute('aria-busy', 'true');
  try { await task(); }
  catch (error) {
    if (error instanceof UsageWriteError) { notice(error.message, true); return; }
    // Only page errors keep the established native connection. Cleanup always
    // clears released values/drafts; the original cause stays on typed errors.
    clearPage();
    if (error instanceof UsageError) view.pageIssue('Local autofill history unavailable', error.message);
    else if (error instanceof PageError) {
      view.pageIssue('Open a sign-in page', error.message);
    } else {
      close();
      if (!identity) view.connection('revoked', 'Reset this browser connection, then use a new code from Zann.');
      else if (!identity.server) { view.connection('unpaired'); notice(error.message, true); }
      else if (error.code === 'locked') view.connection('locked', 'Unlock your vault in the Zann app, then try again.');
      else if (error.code === 'unpaired') view.connection('revoked', 'Use a new one-time code from the Zann app to reconnect.');
      else view.connection('unavailable', 'Keep the Zann app open, then try again.');
    }
  } finally { busy = false; $('controls').disabled = false; $('settings-toggle').disabled = false; document.body.removeAttribute('aria-busy'); }
}
function click(id, task) { $(id).addEventListener('click', event => { if (event.isTrusted) void action(() => task(event)); }); }
async function pairedConnection() {
  close();
  native = await openPaired(chrome, identity);
  view.connection('paired');
}
async function connect() {
  close();
  view.settings(false);
  clearPage();
  if (!identity.server) { view.connection('unpaired'); return; }
  await pairedConnection();
  await refresh();
}
function invalidatePage() {
  clearPage();
  view.pageIssue('Page changed', 'Refresh before filling this page again.');
}
async function query() {
  if (!native || native.closed) throw new Error('Connection closed. Refresh to start a new search.');
  const selected = target;
  searchAbort = new AbortController();
  notice('Searching all logins for this website…');
  const result = await collectLogins(native, new NativeLoginSearch(JSON.stringify(selected.context)), {
    assertCurrent: () => page.assertCurrent(selected),
    onProgress: found => notice(`Searching logins… ${found} matches found.`),
    clock: () => performance.now(), signal: searchAbort.signal
  });
  const ranked = await rankLogins(chrome, identity, navigator.locks, result);
  searchAbort.signal.throwIfAborted(); await page.assertCurrent(selected);
  scope = ranked.scope;
  matches(ranked.items, item => { void action(() => fill(item)); });
  view.formReady(scan);
  notice('');
}
async function selectFrame() {
  clearPage();
  if (!native || native.closed) await pairedConnection();
  target = page.select(snapshot, Number($('frame').value));
  stopWatching = page.watch(target, invalidatePage);
  scan = await page.fields(target, 'scan');
  const forms = scan.forms.map(form => [String(form.index), form.label]);
  options('form', scan.forms.length > 1 ? [['', 'Choose a sign-in form'], ...forms] : forms);
  view.tab('logins'); view.pageReady(snapshot, scan);
  if (scan.forms.length) await query();
}
async function refresh() {
  if (!native || native.closed) await pairedConnection();
  snapshot = await page.frames();
  options('frame', snapshot.frames.map(frame => [String(frame.frameId), frame.frameId === 0 ? 'Main page' : frame.url]));
  $('frame').value = String(snapshot.top.frameId);
  await selectFrame();
}
function formArgs() {
  if (!scan || $('form').disabled || $('form').value === '') throw new PageError('Choose a sign-in form before continuing.');
  return { token: scan.token, form: Number($('form').value) };
}
async function fill(item) {
  const selection = formArgs(), selected = target, selectedScope = scope, selectedIdentity = identity;
  await page.assertCurrent(selected);
  if (!native || native.closed) await pairedConnection();
  const reply = await native.request({ method: 'fill', context: selected.context, item_id: item.item_id, gesture: true, include_totp: $('totp').checked });
  if (reply.status !== 'filled') throw new Error('Unexpected fill reply.');
  try { await fillAndRemember(chrome, selectedIdentity, navigator.locks, selectedScope, item.item_id,
    async () => {
      try { await page.fields(selected, 'fill', { ...selection, value: reply.value, totp: reply.totp, username: item.username }); }
      finally { reply.value = ''; reply.totp = null; }
    }); }
  finally { reply.value = ''; reply.totp = null; }
  notice('Login filled. Review the page before submitting.');
}
async function pair() {
  if (identity.server) throw new Error('Forget the existing connection before pairing again.');
  close();
  const code = $('pairing-code').value;
  $('pairing-code').value = '';
  native = new NativeConnection(chrome, new NativePairing(identity.seed, code, 'Zann Chromium'));
  try {
    await native.connect();
    const server = await native.pair();
    identity = await pinIdentity(chrome, identity, server, navigator.locks);
  } finally { close(); }
  await connect();
}
click('pair', pair);
$('pairing-code').addEventListener('keydown', event => { if (event.isTrusted && event.key === 'Enter') { event.preventDefault(); void action(pair); } });
click('reconnect', connect); click('retry-connection', connect); click('retry-page', refresh); click('refresh', refresh);
async function forget() {
  close(); identity = await forgetIdentity(chrome, identity, create_identity, navigator.locks);
  $('pairing-code').value = ''; scope = null; discard();
  clearPage(); view.settings(false); view.connection('unpaired');
}
click('forget', forget); click('reset-connection', forget);
$('settings-toggle').addEventListener('click', event => { if (event.isTrusted) view.settings($('settings').hidden); });
$('frame').addEventListener('change', event => { if (event.isTrusted) void action(selectFrame); });
$('form').addEventListener('change', () => { discard(); view.formReady(scan); });
for (const tab of ['logins', 'save', 'generate']) click(`tab-${tab}`, () => {
  discard(); $('generated').value = ''; $('use-generated').disabled = true;
  view.tab(tab);
});
click('capture', async () => {
  if (!scope) throw new Error('Query this website with an unlocked desktop vault first.');
  const fields = await page.fields(target, 'capture', formArgs());
  $('title').value = ''; $('username').value = fields.username; $('password').value = fields.password; fields.password = '';
  $('save-login').hidden = false; notice('Review this login, name it, then confirm saving to the selected desktop vault.');
});
$('save-login').addEventListener('submit', event => {
  event.preventDefault(); if (!event.isTrusted) return;
  void action(async () => {
    await page.assertCurrent(target);
    if (!native || native.closed) await pairedConnection();
    const request = { method: 'save', context: target.context, scope, gesture: true, login: { title: $('title').value, username: $('username').value, password: $('password').value } };
    let reply;
    try { reply = await native.request(request); } finally { request.login.password = ''; discard(); }
    if (reply.status !== 'saved') throw new Error('Unexpected save reply.');
    view.tab('logins'); notice('Login saved in Zann. It will sync with your vault.');
  });
});
click('cancel-save', () => { discard(); view.tab('logins'); notice('Draft discarded.'); });
$('length').addEventListener('input', () => { $('length-value').value = $('length').value; });
click('generate-password', () => { $('generated').value = generate_password(Number($('length').value), $('symbols').checked); $('use-generated').disabled = false; notice('Password generated. It is kept only while this popup is open.'); });
click('use-generated', async () => {
  if (!$('generated').value) throw new Error('Generate a password first.');
  await page.fields(target, 'generate', { ...formArgs(), value: $('generated').value });
  $('generated').value = ''; $('use-generated').disabled = true; view.tab('logins'); notice('Password filled. Complete the form and save the login separately.');
});
window.addEventListener('blur', () => { $('pairing-code').value = ''; discard(); $('generated').value = ''; $('use-generated').disabled = true; });
window.addEventListener('pagehide', () => { searchAbort?.abort(new Error('Popup closed.')); stopWatching?.(); close(); clearMatches(); discard(); $('generated').value = ''; });
void action(async () => {
  await siteSettings(chrome);
  await init(); page = new BrowserPage(chrome, checked_context); identity = await loadIdentity(chrome, create_identity, navigator.locks);
  await connect();
});
