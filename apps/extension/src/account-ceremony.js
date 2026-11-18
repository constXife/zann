// Browser/OS adapter only. Domain validation, custody and wrapping stay in Rust.
function bytes(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}
function encoded(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function uuidBytes(value) { return Uint8Array.from(value.replaceAll('-', '').match(/../g), part => parseInt(part, 16)); }
export async function performAccountCeremony(prompt, credentials, signal) {
  const options = prompt.options, registration = options.phase === 'register';
  const descriptor = id => ({ type: 'public-key', id: bytes(id) });
  const publicKey = { challenge: bytes(options.challenge), timeout: 110000,
    userVerification: 'required' };
  if (prompt.require_prf || options.phase === 'login') publicKey.extensions = { prf: { eval: { first: bytes(options.prf_input) } } };
  let credential;
  if (registration) {
    Object.assign(publicKey, { rp: { id: options.rp_id, name: options.rp_name },
      user: { id: uuidBytes(options.user_id), name: options.user_name, displayName: options.user_name },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }], attestation: 'none',
      authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
      excludeCredentials: options.credential_ids.map(descriptor) });
    credential = await credentials.create({ publicKey, signal });
  } else {
    Object.assign(publicKey, { rpId: options.rp_id, allowCredentials: options.credential_ids.map(descriptor) });
    credential = await credentials.get({ publicKey, signal });
  }
  if (!credential || credential.type !== 'public-key') throw new Error('No public key credential returned.');
  const result = credential.getClientExtensionResults();
  const output = result.prf?.results?.first;
  const prf = output ? new Uint8Array(output) : new Uint8Array();
  // A create ceremony can report support without evaluating. The required
  // discoverable test assertion must return usable PRF before Full activation.
  const missingPrf = prompt.require_prf && !registration && prf.length !== 32;
  if (prf.length !== 0 && prf.length !== 32) { prf.fill(0); throw new Error('Invalid PRF result.'); }
  if (missingPrf) { prf.fill(0); return { missingPrf: true }; }
  let delivered = false;
  try {
  const response = registration ? { phase: 'register', credential_id: encoded(credential.rawId),
    client_data_json: encoded(credential.response.clientDataJSON), attestation_object: encoded(credential.response.attestationObject) }
    : { phase: 'assertion', credential_id: encoded(credential.rawId), client_data_json: encoded(credential.response.clientDataJSON),
      authenticator_data: encoded(credential.response.authenticatorData), signature: encoded(credential.response.signature),
      user_handle: credential.response.userHandle ? encoded(credential.response.userHandle) : null };
  delivered = true; return { response, prf };
  } finally { if (!delivered) prf.fill(0); }

}
