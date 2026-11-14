import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, cp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { chromium } from 'playwright';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
export async function fixture({ matches = 2 } = {}) {
  const temporary = await mkdtemp(path.join(tmpdir(), 'zann-chromium-'));
  const ready = path.join(temporary, 'ready.json');
  const daemon = spawn('cargo', ['test', '-p', 'zann-daemon', '--test', 'chromium_fixture', '--', '--ignored', '--exact', 'chromium_fixture'], {
    cwd: root, env: { ...process.env, ZANN_CHROMIUM_READY: ready, ZANN_CHROMIUM_MATCHES: String(matches) }, stdio: ['ignore', 'ignore', 'pipe']
  });
  let context, workerPump; const hosts = new Map();
  try {
  let diagnostic = ''; daemon.stderr.on('data', data => { diagnostic += data; });
  let info;
  for (let attempt = 0; attempt < 300; attempt++) {
    try { info = JSON.parse(await readFile(ready, 'utf8')); break; }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (daemon.exitCode !== null) throw new Error(`Daemon fixture exited: ${diagnostic}`);
    await pause(100);
  }
  if (!info) { daemon.kill(); throw new Error('Daemon fixture did not start.'); }
  const extension = path.join(temporary, 'extension');
  await cp(path.join(root, 'apps/extension/dist'), extension, { recursive: true });
  const manifest = JSON.parse(await readFile(path.join(extension, 'manifest.json')));
  // Test admission only. Shipping activeTab grants access when toolbar popup is invoked.
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const key = publicKey.export({ type: 'spki', format: 'der' });
  manifest.key = key.toString('base64');
  manifest.host_permissions = ['https://example.test/*', 'https://evil.test/*'];
  await writeFile(path.join(extension, 'manifest.json'), JSON.stringify(manifest));
  const id = [...createHash('sha256').update(key).digest().subarray(0, 16)].flatMap(byte => [byte >> 4, byte & 15]).map(value => String.fromCharCode(97 + value)).join('');
  context = await chromium.launchPersistentContext(path.join(temporary, 'profile'), {
    channel: 'chromium', headless: true,
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`]
  });
  function openHost(page, connection) {
    const host = spawn(path.join(root, 'target/debug/zann-native-host'), ['--root', info.root], { stdio: ['pipe', 'pipe', 'ignore'] });
    hosts.set(connection, host); let buffer = Buffer.alloc(0);
    host.stdout.on('data', data => {
      buffer = Buffer.concat([buffer, data]);
      while (buffer.length >= 4 && buffer.length >= 4 + buffer.readUInt32LE(0)) {
        const size = buffer.readUInt32LE(0), packet = JSON.parse(buffer.subarray(4, size + 4)); buffer = buffer.subarray(size + 4);
        void page.evaluate(({ connection, packet }) => globalThis.__nativeDeliver(connection, packet), { connection, packet }).catch(() => {});
      }
    });
    host.on('exit', () => { hosts.delete(connection); void page.evaluate(connection => globalThis.__nativeClosed(connection), connection).catch(() => {}); });
  }
  function sendHost({ connection, packet }) {
    const bytes = Buffer.from(JSON.stringify(packet)), header = Buffer.alloc(4); header.writeUInt32LE(bytes.length);
    hosts.get(connection)?.stdin.write(Buffer.concat([header, bytes]));
  }
  await context.exposeBinding('__nativeOpen', ({ page }, connection) => openHost(page, connection));
  await context.exposeBinding('__nativeSend', (_, request) => sendHost(request));
  await context.exposeBinding('__nativeDisconnect', (_, connection) => { hosts.get(connection)?.stdin.end(); });
  await context.addInitScript(() => {
    if (location.protocol !== 'chrome-extension:') return;
    const ports = new Map();
    globalThis.__nativeDeliver = (id, packet) => ports.get(id)?.message.forEach(fn => fn(packet));
    globalThis.__nativeClosed = id => { ports.get(id)?.disconnect.forEach(fn => fn()); ports.delete(id); };
    chrome.runtime.connectNative = () => {
      const id = crypto.randomUUID(), entry = { message: [], disconnect: [] }; ports.set(id, entry);
      void globalThis.__nativeOpen(id);
      return { onMessage: { addListener: fn => entry.message.push(fn) }, onDisconnect: { addListener: fn => entry.disconnect.push(fn) },
        postMessage: packet => { void globalThis.__nativeSend({ connection: id, packet }); }, disconnect: () => { void globalThis.__nativeDisconnect(id); } };
    };
    // A popup opened as a test tab is otherwise its own active tab. All returned
    // URLs and document IDs still come from Chrome; DOM never supplies them.
    const query = chrome.tabs.query.bind(chrome.tabs);
    chrome.tabs.query = () => query({ url: 'https://example.test/*' });
  });
  await context.route('https://**/*', route => route.fulfill({ contentType: 'text/html', body: `<!doctype html><title>Login fixture</title><form><label>Username<input name="username" autocomplete="username"></label><input name="password" type="password" autocomplete="current-password"><input name="otp" autocomplete="one-time-code"><button>Log in</button></form><iframe src="https://evil.test/frame"></iframe>` }));
  const site = await context.newPage(); await site.goto('https://example.test/login');
  const popup = await context.newPage();
  const errors = []; popup.on('pageerror', error => errors.push(error.message));
  await popup.goto(`chrome-extension://${id}/popup.html`);
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker');
  // Worker test launcher uses the same real stdio host. Only process launch is
  // replaced; no shipping transport hook, browser identity or policy is mocked.
  await worker.evaluate(() => {
    const ports = new Map(); globalThis.__nativeOut = [];
    globalThis.__nativeDeliver = (id, packet) => ports.get(id)?.message.forEach(fn => fn(packet));
    globalThis.__nativeClosed = id => { ports.get(id)?.disconnect.forEach(fn => fn()); ports.delete(id); };
    chrome.runtime.connectNative = () => {
      const id = crypto.randomUUID(), entry = { message: [], disconnect: [] }; ports.set(id, entry);
      if (globalThis.__failNextNative) {
        globalThis.__failNextNative = false; queueMicrotask(() => globalThis.__nativeClosed(id));
      } else globalThis.__nativeOut.push({ type: 'open', id });
      return { onMessage: { addListener: fn => entry.message.push(fn) }, onDisconnect: { addListener: fn => entry.disconnect.push(fn) },
        postMessage: packet => globalThis.__nativeOut.push({ type: 'send', id, packet }), disconnect: () => globalThis.__nativeOut.push({ type: 'close', id }) };
    };
  });
  let pumping = false;
  workerPump = setInterval(async () => {
    if (pumping) return; pumping = true;
    try {
      for (const event of await worker.evaluate(() => globalThis.__nativeOut.splice(0))) {
        if (event.type === 'open') openHost(worker, event.id);
        if (event.type === 'send') sendHost({ connection: event.id, packet: event.packet });
        if (event.type === 'close') hosts.get(event.id)?.stdin.end();
      }
    } catch (error) { if (!context?.pages().length) return; errors.push(error.message); }
    finally { pumping = false; }
  }, 10);
  return { site, popup, worker, info, errors, async close() {
    clearInterval(workerPump);
    for (const host of hosts.values()) host.kill(); await context.close();
    await rm(ready, { force: true });
    if (daemon.exitCode === null) { await Promise.race([new Promise(resolve => daemon.once('exit', resolve)), pause(2000)]); if (daemon.exitCode === null) daemon.kill(); }
    await rm(temporary, { recursive: true, force: true });
  } };
  } catch (error) {
    clearInterval(workerPump);
    for (const host of hosts.values()) host.kill();
    await context?.close(); daemon.kill();
    await rm(temporary, { recursive: true, force: true });
    throw error;
  }
}

export async function chooser(site) {
  for (let i = 0; i < 150; i++) {
    const frame = site.frames().find(frame => frame.url().includes('/inline.html#'));
    if (frame) return frame;
    await pause(50);
  }
  throw new Error('Inline chooser did not mount.');
}
export async function closed(site) {
  for (let i = 0; i < 150; i++) {
    if (!site.frames().some(frame => frame.url().includes('/inline.html#'))) return;
    await pause(25);
  }
  throw new Error('Filled chooser did not close.');
}
