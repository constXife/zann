import { NativeClient } from './wasm/zann_browser.js';
import { NativeConnection } from './native.js';
export async function pairedConnection(chrome, identity) {
  if (!identity?.server) throw new Error('Pair with Zann using the toolbar first.');
  const connection = new NativeConnection(chrome, new NativeClient(identity.seed, identity.server));
  try {
    await connection.connect();
    const reply = await connection.request({ method: 'pair_status' });
    if (reply.status !== 'paired') throw new Error('Connect this browser using a new code from Zann.');
    return connection;
  } catch (error) { connection.close(); throw error; }
}
