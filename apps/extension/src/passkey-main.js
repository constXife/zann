// Page-world adapter: only standard WebAuthn input/output crosses this bridge.
export function installPasskeyShim() {
  if (globalThis.__zannPasskeys) return;
  globalThis.__zannPasskeys = true;
  const encode = value => {
    const bytes = new Uint8Array(value instanceof ArrayBuffer ? value : value.buffer, value.byteOffset ?? 0, value.byteLength);
    if (bytes.length > 4096) throw new DOMException('Passkey input is too large.', 'NotSupportedError');
    return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  };
  const decode = value => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0)).buffer;
  const credential = value => {
    const response = { clientDataJSON: decode(value.client_data_json), authenticatorData: decode(value.authenticator_data) };
    if (value.attestation_object) {
      response.attestationObject = decode(value.attestation_object);
      response.getTransports = () => ['internal'];
      response.getAuthenticatorData = () => response.authenticatorData;
      response.getPublicKeyAlgorithm = () => -7;
      response.getPublicKey = () => decode(value.public_key_spki);
      Object.setPrototypeOf(response, AuthenticatorAttestationResponse.prototype);
    } else {
      response.signature = decode(value.signature); response.userHandle = decode(value.user_handle);
      Object.setPrototypeOf(response, AuthenticatorAssertionResponse.prototype);
    }
    const result = { id: value.credential_id, rawId: decode(value.credential_id), type: 'public-key', authenticatorAttachment: 'platform', response,
      getClientExtensionResults: () => ({}) };
    result.toJSON = () => ({ id: value.credential_id, rawId: value.credential_id, type: 'public-key', authenticatorAttachment: 'platform', clientExtensionResults: {},
      response: value.attestation_object ? { clientDataJSON: value.client_data_json, attestationObject: value.attestation_object, authenticatorData: value.authenticator_data, publicKey: value.public_key_spki, publicKeyAlgorithm: -7, transports: ['internal'] }
        : { clientDataJSON: value.client_data_json, authenticatorData: value.authenticator_data, signature: value.signature, userHandle: value.user_handle } });
    Object.setPrototypeOf(result, PublicKeyCredential.prototype);
    return result;
  };
  for (const kind of ['create', 'get']) {
    const original = navigator.credentials[kind].bind(navigator.credentials);
    navigator.credentials[kind] = function(options) {
      if (!options?.publicKey) return original(options);
      if (options.mediation === 'conditional') return Promise.reject(new DOMException('Conditional passkeys are unavailable.', 'NotSupportedError'));
      return new Promise((resolve, reject) => {
        const id = crypto.randomUUID(), input = { ...options.publicKey, challenge: encode(options.publicKey.challenge) };
        if (input.user) input.user = { ...input.user, id: encode(input.user.id) };
        for (const field of ['excludeCredentials', 'allowCredentials']) if (input[field]) {
          if (!Array.isArray(input[field]) || input[field].length > 64) throw new DOMException('Credential list is too large.', 'NotSupportedError');
          input[field] = input[field].map(c => ({ ...c, id: encode(c.id) }));
        }
        const finish = (value, error) => { clearTimeout(timer); removeEventListener('message', receive); options.signal?.removeEventListener('abort', abort); error ? reject(error) : resolve(credential(value)); };
        const receive = event => {
          if (event.source !== window || event.data?.channel !== 'zann-passkey-result' || event.data.id !== id) return;
          if (event.data.error) finish(null, new DOMException(event.data.error, 'NotAllowedError'));
          else finish(event.data.response);
        };
        const abort = () => { window.postMessage({ channel: 'zann-passkey-cancel', id }, location.origin); finish(null, new DOMException('Passkey request canceled.', 'AbortError')); };
        const timer = setTimeout(abort, Math.min(input.timeout ?? 30000, 30000));
        addEventListener('message', receive); options.signal?.addEventListener('abort', abort, { once: true });
        if (options.signal?.aborted) { abort(); return; }
        window.postMessage({ channel: 'zann-passkey-request', id, kind, options: input }, location.origin);
      });
    };
  }
}
