// One ephemeral owner per operation/surface. Native packets never enter page messages.
export class NativeConnection {
  constructor(chrome, client) {
    this.client = client;
    this.port = chrome.runtime.connectNative('com.rlyeh.zann');
    this.waiter = null;
    this.inbox = [];
    this.closed = false;
    this.port.onMessage.addListener(packet => {
      if (this.closed) return;
      if (this.waiter) {
        const waiter = this.waiter; this.waiter = null; waiter.resolve(packet);
      } else if (this.inbox.length === 0) this.inbox.push(packet);
      else this.close(new Error('Unexpected native message. Reconnect explicitly.'));
    });
    this.port.onDisconnect.addListener(() => {
      // Consume lastError without printing native/browser diagnostics or packets.
      const failed = chrome.runtime.lastError;
      this.close(new Error(failed ? 'Native host unavailable. Check installation and open Zann.' : 'Desktop connection closed. Reconnect explicitly.', { cause: failed }));
    });
  }
  next() {
    if (this.closed) return Promise.reject(new Error('Connection closed. Reconnect explicitly.'));
    if (this.waiter) return Promise.reject(new Error('Native request already in flight.'));
    if (this.inbox.length) return Promise.resolve(this.inbox.shift());
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.close(new Error('Desktop request timed out. Its outcome may be unknown; it was not retried.')), 4500);
      this.waiter = { resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } };
    });
  }
  async connect() {
    const hello = await this.next();
    this.port.postMessage(JSON.parse(this.client.connect(JSON.stringify(hello))));
    this.client.finish(JSON.stringify(await this.next()));
  }
  async request(request) {
    if (this.closed) throw new Error('Connection closed. Reconnect explicitly.');
    this.port.postMessage(JSON.parse(this.client.request(JSON.stringify(request))));
    const reply = JSON.parse(this.client.reply(JSON.stringify(await this.next())));
    if (reply.status === 'error') {
      const messages = { locked: 'Unlock your vault in Zann, then reconnect.', unpaired: 'Browser access was revoked or is not connected. Forget this connection and pair using a new code from Zann.', refused: 'Desktop refused this operation.', limit: 'Desktop resource limit reached.', timeout: 'Desktop timed out. The operation was not retried.', internal: 'Desktop operation failed.' };
      const error = new Error(messages[reply.code] ?? 'Invalid desktop error.');
      error.code = reply.code; throw error;
    }
    return reply;
  }
  async pair() {
    try {
      this.port.postMessage(JSON.parse(this.client.begin()));
      this.port.postMessage(JSON.parse(this.client.confirm(JSON.stringify(await this.next()))));
      return this.client.complete(JSON.stringify(await this.next()));
    } catch (cause) {
      // UI boundary translation retains the original cryptographic/transport error.
      throw new Error('Could not connect. Check the code or create a new one in Zann; codes expire after two minutes and five attempts.', { cause });
    }
  }
  close(error = new Error('Connection closed.')) {
    if (this.closed) return;
    this.closed = true;
    this.waiter?.reject(error); this.waiter = null; this.inbox.length = 0;
    this.port.disconnect(); this.client.free();
  }
}
