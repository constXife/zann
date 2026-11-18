import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { performAccountCeremony } from '../src/account-ceremony.js';
import { accountWindows } from '../src/account-background.js';
globalThis.crypto ??= webcrypto;
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const prompt = (phase, require_prf = true) => ({ require_prf, options: { phase, challenge: b64(new Uint8Array(32).fill(1)), rp_id: 'example.test', rp_name: 'Zann', user_id: '11111111-1111-4111-8111-111111111111', user_name: 'test@example.test', credential_ids: [], prf_input: b64(new Uint8Array(32).fill(2)) } });
function credential(prf) { return { type: 'public-key', rawId: new Uint8Array([3]).buffer, response: { clientDataJSON: new Uint8Array([4]).buffer, attestationObject: new Uint8Array([5]).buffer, authenticatorData: new Uint8Array([6]).buffer, signature: new Uint8Array([7]).buffer, userHandle: new Uint8Array(16).fill(8).buffer }, getClientExtensionResults: () => prf ? { prf: { results: { first: prf.buffer } } } : {} }; }
test('Full uses UV, resident ES256 and retains PRF only in the separate native result', async () => {
  const output = new Uint8Array(32).fill(9);
  const result = await performAccountCeremony(prompt('register'), { create: async ({ publicKey }) => {
    assert.equal(publicKey.authenticatorSelection.userVerification, 'required');
    assert.equal(publicKey.authenticatorSelection.residentKey, 'required');
    assert.deepEqual(publicKey.pubKeyCredParams, [{ type: 'public-key', alg: -7 }]);
    assert.equal(publicKey.extensions.prf.eval.first.length, 32);
    return credential(output);
  } });
  assert.equal(result.prf.length, 32); assert.ok(!JSON.stringify(result.response).includes('prf'));
  result.prf.fill(0); assert.equal(output[0], 0);
});
test('Full test fails explicitly without PRF; Auth-only never requests it', async () => {
  const missing = await performAccountCeremony(prompt('test'), { get: async ({ publicKey }) => {
    assert.equal(publicKey.userVerification, 'required'); assert.deepEqual(publicKey.allowCredentials, []);
    return credential();
  } });
  assert.deepEqual(missing, { missingPrf: true });
  const auth = await performAccountCeremony(prompt('test', false), { get: async ({ publicKey }) => { assert.equal(publicKey.extensions, undefined); return credential(); } });
  assert.equal(auth.prf.length, 0);
});
test('PRF output is cleared if the public assertion cannot be serialized', async () => {
  const output = new Uint8Array(32).fill(9), value = credential(output);
  Object.defineProperty(value.response, 'signature', { get() { throw new TypeError('broken signature response'); } });
  await assert.rejects(performAccountCeremony(prompt('test'), { get: async () => value }), TypeError);
  assert.ok(output.every(value => value === 0));
});
function event() { const listeners = []; return { addListener: fn => listeners.push(fn), fire: (...args) => listeners.forEach(fn => fn(...args)) }; }
function chromeFixture() {
  const chrome = { runtime: { id: 'extension', getURL: path => `chrome-extension://extension/${path}`, onMessage: event(), onConnect: event() }, windows: { create: async ({url}) => { chrome.url = url; return {id: 1, tabs: [{id: 2}]}; }, update: async()=>{}, remove: async()=>{}, onRemoved: event() }, permissions: { onRemoved: event() }, storage: { onChanged: event() } };
  accountWindows(chrome); return chrome;
}
const settle = () => new Promise(resolve => setImmediate(resolve));
function port(sender) { const value = {name:'zann-account-document',sender,onDisconnect:event(),onMessage:event(),messages:[],closed:false}; value.disconnect=()=>{value.closed=true;value.onDisconnect.fire();}; value.postMessage=message=>value.messages.push(message); return value; }
test('Only the trusted popup can open an account window; exact top document is single-use', async () => {
  const chrome = chromeFixture(); let rejected;
  chrome.runtime.onMessage.fire({type:'zann-account-open'}, {id:'extension', url:'https://evil.test/'}, reply=>rejected=reply);
  assert.equal(rejected.accepted,false); assert.equal(chrome.url,undefined);
  chrome.runtime.onMessage.fire({type:'zann-account-open'}, {id:'extension',url:chrome.runtime.getURL('popup.html'),frameId:0,tab:{id:8}},()=>{});
  await settle();
  const wrong=port({id:'extension',url:chrome.url,frameId:1,documentId:'frame',tab:{id:2,windowId:1}}); chrome.runtime.onConnect.fire(wrong); assert.equal(wrong.closed,true);
  const valid=port({id:'extension',url:chrome.url,frameId:0,documentId:'document',tab:{id:2,windowId:1}}); chrome.runtime.onConnect.fire(valid); await settle(); assert.deepEqual(valid.messages,[{ready:true}]);
  const replay=port({...valid.sender,documentId:'other'}); chrome.runtime.onConnect.fire(replay); assert.equal(replay.closed,true);
  chrome.permissions.onRemoved.fire({origins:['https://example.test/*']}); assert.equal(valid.closed,true);
});
