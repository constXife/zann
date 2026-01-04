#!/usr/bin/env python3
import base64
import json
import sys
from getpass import getpass
import hashlib

try:
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
except Exception:
    XChaCha20Poly1305 = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except Exception:
    ChaCha20Poly1305 = None


def b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def aead_new(aead: str, key: bytes):
    if aead == "xchacha20poly1305":
        if XChaCha20Poly1305 is None:
            raise RuntimeError("XChaCha20Poly1305 is not available in this Python build.")
        return XChaCha20Poly1305(key), 24
    if aead == "chacha20poly1305":
        if ChaCha20Poly1305 is None:
            raise RuntimeError("ChaCha20Poly1305 is not available in this Python build.")
        return ChaCha20Poly1305(key), 12
    raise RuntimeError(f"unsupported AEAD: {aead}")


def main() -> int:
    try:
        with open("demo.json", "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except FileNotFoundError:
        sys.stderr.write("demo.json not found\n")
        return 2

    aead = payload["aead"]
    vault_key_enc = b64d(payload["vault_key_enc_b64"])
    enc_dek = b64d(payload["enc_dek_b64"])
    nonce_payload = b64d(payload["nonce_payload_b64"])
    ciphertext = b64d(payload["ciphertext_b64"])

    master_password = getpass("Master password: ")
    if not master_password:
        sys.stderr.write("master password cannot be empty\n")
        return 2

    kdf = payload["kdf"]
    params = kdf["params"]
    kdf_salt = b64d(kdf["salt_b64"])
    master_key = hashlib.scrypt(
        master_password.encode("utf-8"),
        salt=kdf_salt,
        n=int(params["n"]),
        r=int(params["r"]),
        p=int(params["p"]),
        dklen=int(params["dk_len"]),
    )

    wrap_master, nonce_len = aead_new(aead, master_key)
    nonce_vault, ct_vault = vault_key_enc[:nonce_len], vault_key_enc[nonce_len:]
    try:
        vault_key = wrap_master.decrypt(nonce_vault, ct_vault, b"")
    except Exception:
        sys.stderr.write("decrypt failed (wrong master password?)\n")
        return 3

    wrap, nonce_len = aead_new(aead, vault_key)
    nonce_dek, ct_dek = enc_dek[:nonce_len], enc_dek[nonce_len:]
    dek = wrap.decrypt(nonce_dek, ct_dek, b"")

    payload_cipher, _ = aead_new(aead, dek)
    plaintext = payload_cipher.decrypt(nonce_payload, ciphertext, b"")

    sys.stdout.write(plaintext.decode("utf-8") + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
