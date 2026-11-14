// Serialized by scripting.executeScript into the isolated world; no imports,
// page-provided origin authority or submit listener. Shared by both UI surfaces.
export function pageFields(command) {
  if (location.href !== command.frameURL || top.location.href !== command.topURL) return { ok: false, error: 'Page changed.' };
  const visible = field => field instanceof HTMLInputElement && field.isConnected &&
    !field.disabled && !field.readOnly && !field.closest('[inert]') &&
    field.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true }) &&
    field.getClientRects().length > 0;
  const key = command.namespace === 'inline' ? '__zannInlineFieldsV1' : '__zannPopupFieldsV1';
  const kind = (form, field) => field === form.totp ? 'otp' : field.autocomplete === 'new-password' ? 'new-password' : 'login';
  if (command.operation === 'scan') {
    const inputs = []; const roots = [document]; let visited = 0;
    for (let index = 0; index < roots.length; index++) {
      const walker = document.createTreeWalker(roots[index], NodeFilter.SHOW_ELEMENT);
      for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        if (++visited > 5000 || roots.length > 100 || inputs.length > 200) return { ok: false, error: 'Page is too large to inspect safely.' };
        if (node.shadowRoot) roots.push(node.shadowRoot);
        if (node instanceof HTMLInputElement && visible(node)) inputs.push(node);
      }
    }
    const groups = new Map();
    for (const input of inputs) {
      const owner = input.form ?? input.getRootNode();
      if (!groups.has(owner)) groups.set(owner, []);
      groups.get(owner).push(input);
    }
    const forms = [];
    for (const fields of groups.values()) {
      const passwords = fields.filter(field => field.type === 'password');
      const totp = fields.filter(field => field.autocomplete === 'one-time-code');
      if (!passwords.length && !totp.length) continue;
      const explicit = fields.filter(field => ['username', 'email'].includes(field.autocomplete) || field.type === 'email');
      const before = fields.slice(0, fields.indexOf(passwords[0])).filter(field => field.type === 'text');
      const username = explicit.length === 1 ? explicit[0] : explicit.length === 0 ? before.at(-1) : null;
      forms.push({ passwords, username, totp: totp.length === 1 ? totp[0] : null });
    }
    // References are private to the isolated world and replaced on each scan.
    const token = crypto.randomUUID();
    globalThis[key] = { token, forms };
    return { ok: true, token, forms: forms.map((form, index) => ({ index, label: `Form ${index + 1}${form.username ? ' · ' + (form.username.labels?.[0]?.textContent?.trim() || form.username.name || 'username').slice(0, 60) : ''}`, totp: Boolean(form.totp) })) };
  }
  const state = globalThis[key];
  if (command.operation === 'locate') {
    if (state?.token !== command.token || !visible(command.field)) return { ok: false, error: 'Field unavailable.' };
    const index = state.forms.findIndex(form => form.username === command.field || form.passwords.includes(command.field) || form.totp === command.field);
    if (index < 0) return { ok: false, error: 'No login form.' };
    state.focus = { form: index, field: command.field };
    return { ok: true, form: index };
  }
  const form = state?.token === command.token ? state.forms[command.form] : null;
  if (!form || !form.passwords.every(field => visible(field) && field.type === 'password') || (form.username && !visible(form.username)) || (form.totp && (!visible(form.totp) || form.totp.autocomplete !== 'one-time-code'))) return { ok: false, error: 'Form changed. Refresh before continuing.' };
  if (command.namespace === 'inline') {
    if (state.focus?.form !== command.form || !visible(state.focus.field)) return { ok: false, error: 'Focused field changed.' };
    const focusedKind = kind(form, state.focus.field);
    if (command.operation === 'context') return { ok: true, kind: focusedKind };
    const expected = { fill: 'login', generate: 'new-password', otp: 'otp' }[command.operation];
    if (expected !== focusedKind) return { ok: false, error: 'Field action no longer matches the focused field.' };
  }
  if (command.operation === 'capture') {
    const passwords = form.passwords.map(field => field.value);
    if (!passwords[0] || !passwords.every(value => value === passwords[0]) || passwords[0].length > 4096) return { ok: false, error: 'Enter one password or matching confirmation fields first.' };
    return { ok: true, username: form.username?.value ?? '', password: passwords[0] };
  }
  if (!['fill', 'generate', 'otp'].includes(command.operation)) return { ok: false, error: 'Unknown field action.' };
  const newPasswords = form.passwords.filter(field => field.autocomplete === 'new-password');
  const targets = command.operation === 'otp' ? (form.totp && command.totp ? [form.totp] : []) : command.operation === 'generate' ? (newPasswords.length ? newPasswords : form.passwords.length === 1 ? form.passwords : []) : form.passwords.filter(field => field.autocomplete !== 'new-password');
  if (!targets.length || (command.operation === 'fill' && targets.length !== 1) || (command.totp && !form.totp)) return { ok: false, error: 'Select an unambiguous login form.' };
  const set = (field, value) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(field, value);
    field.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    field.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
  };
  if (command.operation === 'fill' && form.username && command.username !== null) set(form.username, command.username);
  for (const field of targets) set(field, command.operation === 'otp' ? command.totp : command.value);
  if (command.operation === 'fill' && command.totp) set(form.totp, command.totp);
  // Never focus, click, submit, or read back a released value.
  return { ok: true };
}
