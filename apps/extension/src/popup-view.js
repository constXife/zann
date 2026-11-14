// Rendering only. Native authorization and browser document admission have
// their existing owners; no connection preferences or secrets are cached here.
import { $, notice, loginList } from './ui.js';

export function settings(open) {
  $('settings').hidden = !open; $('content').hidden = open;
  $('settings-toggle').setAttribute('aria-expanded', String(open));
}
export function connection(state, error) {
  $('connection').textContent = { paired: 'Connected', unpaired: 'Not connected', locked: 'Locked', unavailable: 'Unavailable', revoked: 'Not connected' }[state];
  $('pairing').hidden = state !== 'unpaired';
  $('connection-settings').hidden = state === 'unpaired';
  $('connection-issue').hidden = ['paired', 'unpaired'].includes(state);
  if (state !== 'paired') { $('workspace').hidden = true; $('page-issue').hidden = true; $('page-target').hidden = true; }
  $('reset-connection').hidden = state !== 'revoked'; $('retry-connection').hidden = state === 'revoked';
  $('connection-title').textContent = { locked: 'Unlock Zann', unavailable: 'Open Zann', revoked: 'Connect this browser again' }[state] ?? '';
  $('connection-message').textContent = error ?? '';
  notice('');
}
export function pageIssue(title, message) {
  $('workspace').hidden = true; $('page-issue').hidden = false;
  $('page-title').textContent = title; $('page-message').textContent = message;
  notice('');
}
export function pageReady(snapshot, scan) {
  $('site-title').textContent = new URL(snapshot.top.url).hostname;
  $('page-issue').hidden = true; $('workspace').hidden = false;
  $('frame-choice').hidden = snapshot.frames.length <= 1;
  $('form-choice').hidden = scan.forms.length <= 1;
  $('page-target').hidden = snapshot.frames.length <= 1 && scan.forms.length <= 1;
  $('page-target').open = scan.forms.length > 1;
  formReady(scan);
  if (!scan.forms.length) pageIssue('No sign-in fields found', 'Open the sign-in form on this website, then try again.');
}
export function formReady(scan) {
  const form = scan?.forms.find(form => String(form.index) === $('form').value);
  $('totp-choice').hidden = !form?.totp; $('totp').checked = false;
  loginList.setDisabled(!form);
}
export function tab(selected) {
  for (const name of ['logins', 'save', 'generate']) $(name).hidden = name !== selected;
  $('tab-logins').hidden = selected === 'logins';
  $('secondary-actions').hidden = selected !== 'logins';
}
