import { NativeLoginSearch, generate_password } from './wasm/zann_browser.js';
import { collectLogins } from './search.js';
import { pairedConnection } from './paired.js';
import { hasSite } from './sites.js';
import { identifyChooser } from './chooser-document.js';
import { rankLogins, fillAndRemember } from './usage.js';

// One document-bound chooser. Only privileged injection receives released values.
export class InlineSession {
  constructor(broker, port, ready) {
    this.broker = broker; this.chrome = broker.chrome; this.port = port; this.ready = ready; this.epoch = 0;
    port.onMessage.addListener(message => {
      if (message.type === 'close') this.reset();
      else if (message.type === 'open') {
        this.reset(); const epoch = this.epoch;
        void this.open(message, epoch).catch(error => this.failed(error, epoch));
      } else if (message.type === 'key' && ['ArrowDown', 'ArrowUp', 'Enter'].includes(message.key)) this.picker?.postMessage({ type: 'key', key: message.key });
    });
    port.onDisconnect.addListener(() => { this.reset(); broker.pages.delete(this); });
  }
  reset() {
    this.epoch++; this.busy = false; clearTimeout(this.timer); this.abort?.abort(new Error('Suggestions closed.'));
    this.native?.close(); this.native = null; this.items = null; this.scope = null; this.generated = ''; this.selection = null;
    this.failure = null;
    if (this.token) this.broker.tokens.delete(this.token); this.token = null;
    const picker = this.picker; this.picker = null; picker?.disconnect();
  }
  async current(epoch) {
    if (epoch !== this.epoch) throw new Error('Suggestions changed.');
    await this.page.assertCurrent(this.target);
    if (!await hasSite(this.chrome, this.target.top.url)) throw new Error('Site permission was removed.');
    if (epoch !== this.epoch) throw new Error('Suggestions changed.');
  }
  async open(message, epoch) {
    const { page, target } = await this.ready;
    if (epoch !== this.epoch) return;
    this.page = page; this.target = target;
    await this.current(epoch);
    if (!Number.isSafeInteger(message.form) || message.form < 0 || message.form > 200 || !/^[0-9a-f-]{36}$/.test(message.token) || !Number.isSafeInteger(message.request)) throw new Error('Invalid form selection.');
    this.selection = { token: message.token, form: message.form, namespace: 'inline' };
    this.request = message.request;
    const context = await this.page.fields(this.target, 'context', this.selection);
    await this.current(epoch); this.kind = context.kind;
    this.token = crypto.randomUUID(); this.broker.tokens.set(this.token, this);
    this.timer = setTimeout(() => { this.port.postMessage({ type: 'hide' }); this.reset(); }, 60000);
    this.port.postMessage({ type: 'mount', request: message.request, url: `${this.chrome.runtime.getURL('inline.html')}#${this.token}` });
  }
  async attach(port) {
    const epoch = this.epoch;
    if (this.picker) throw new Error('Chooser already connected.');
    await this.current(epoch);
    const sender = port.sender;
    if (sender.id !== this.chrome.runtime.id || sender.tab?.id !== this.target.tabId || !sender.documentId || sender.frameId === 0 || new URL(sender.url).pathname !== '/inline.html' || !sender.url.startsWith('chrome-extension://')) throw new Error('Untrusted chooser document.');
    await this.current(epoch);
    if (this.picker) throw new Error('Chooser already connected.');
    this.picker = port;
    port.onDisconnect.addListener(() => { if (this.picker === port) { this.port.postMessage({ type: 'hide' }); this.reset(); } });
    await identifyChooser(port, new URL(this.target.top.url).origin);
    await this.current(epoch);
    port.onMessage.addListener(message => {
      if (this.picker !== port) return;
      if (message.type === 'close') { this.port.postMessage({ type: 'hide' }); this.reset(); return; }
      if (message.type === 'size') {
        if (Number.isInteger(message.height) && message.height >= 56 && message.height <= 320) this.port.postMessage({ type: 'resize', request: this.request, height: message.height });
        return;
      }
      if (this.busy) return;
      this.busy = true;
      void this.action(message, epoch).catch(error => this.failed(error, epoch)).finally(() => { if (epoch === this.epoch) this.busy = false; });
    });
    this.busy = true;
    this.picker.postMessage({ type: 'context', host: new URL(this.target.top.url).host, kind: this.kind });
    try { if (this.kind === 'new-password') this.picker.postMessage({ type: 'new-password' }); else await this.search(epoch); }
    catch (error) { this.failed(error, epoch); }
    finally { if (epoch === this.epoch) this.busy = false; }
  }
  async connection(epoch) {
    this.native?.close(); this.native = null;
    const identity = await this.broker.identity();
    await this.current(epoch);
    const native = await pairedConnection(this.chrome, identity);
    if (epoch !== this.epoch) { native.close(); throw new Error('Suggestions changed.'); }
    this.native = native; return { native, identity };
  }
  async search(epoch) {
    this.picker.postMessage({ type: 'loading' });
    this.abort = new AbortController();
    const { native, identity } = await this.connection(epoch);
    const result = await collectLogins(native, new NativeLoginSearch(JSON.stringify(this.target.context)), {
      assertCurrent: () => this.current(epoch), onProgress: () => {}, clock: () => performance.now(), signal: this.abort.signal
    });
    const ranked = await rankLogins(this.chrome, identity, navigator.locks, result);
    await this.current(epoch); this.items = ranked.items; this.scope = ranked.scope;
    this.picker.postMessage({ type: 'matches', items: this.items });
    native.close(); this.native = null;
  }
  async action(message, epoch) {
    await this.current(epoch);
    const context = await this.page.fields(this.target, 'context', this.selection);
    if (context.kind !== this.kind) throw new Error('Focused field changed. Reopen suggestions.');
    if (message.type === 'retry') {
      this.generated = '';
      if (this.kind === 'new-password') this.picker.postMessage({ type: 'new-password' }); else await this.search(epoch);
      return;
    }
    if (message.type === 'generate') {
      if (this.kind !== 'new-password') throw new Error('Select a new-password field to generate a password.');
      this.generated = generate_password(24, true);
      this.picker.postMessage({ type: 'generated', length: 24 }); return;
    }
    if (message.type === 'use-generated') {
      if (this.kind !== 'new-password' || !this.generated) throw new Error('Generate a password in a new-password field first.');
      try { await this.page.fields(this.target, 'generate', { ...this.selection, value: this.generated }); }
      finally { this.generated = ''; }
    } else if (message.type === 'fill') {
      if (this.kind !== 'login' && this.kind !== 'otp') throw new Error('Select a login or one-time-code field.');
      const item = this.items?.find(item => item.item_id === message.item_id);
      if (!item) throw new Error('Login is no longer selected.');
      const { native, identity } = await this.connection(epoch);
      const scope = this.scope;
      const reply = await native.request({ method: 'fill', context: this.target.context, item_id: item.item_id, gesture: true, include_totp: this.kind === 'otp' });
      try {
        await this.current(epoch);
        if (reply.status !== 'filled') throw new Error('Unexpected fill reply.');
        await fillAndRemember(this.chrome, identity, navigator.locks, scope, item.item_id, async () => {
          try {
            if (this.kind === 'otp') {
              if (!reply.totp) throw new Error('У этой записи нет кода 2FA. Выберите другую запись.');
              // The existing signed fill contract returns password + optional code.
              // In OTP context only the code reaches DOM; the unused value is cleared.
              reply.value = '';
              await this.page.fields(this.target, 'otp', { ...this.selection, totp: reply.totp });
            } else await this.page.fields(this.target, 'fill', { ...this.selection, value: reply.value, username: item.username });
          } finally { reply.value = ''; reply.totp = null; }
        });
      } finally { reply.value = ''; reply.totp = null; native.close(); }
    } else throw new Error('Unknown chooser action.');
    await this.current(epoch);
    this.port.postMessage({ type: 'hide' }); this.reset();
  }
  failed(error, epoch) {
    if (epoch !== this.epoch) return;
    // Terminal UI boundary: preserve Error/source, never emit bodies or secrets.
    this.failure = error;
    this.native?.close(); this.native = null; this.items = null; this.generated = '';
    this.picker?.postMessage({ type: 'error', message: error.message, code: error.code });
  }
  disable() { this.port.postMessage({ type: 'disabled' }); this.reset(); this.port.disconnect(); }
  hide() { this.port.postMessage({ type: 'hide' }); this.reset(); }
}
