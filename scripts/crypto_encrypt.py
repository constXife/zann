#!/usr/bin/env python3
import base64
import json
import os
import sys
from getpass import getpass
import hashlib

try:
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
    AEAD = "xchacha20poly1305"
    NonceLen = 24
except Exception:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        AEAD = "chacha20poly1305"
        NonceLen = 12
        sys.stderr.write(
            "XChaCha20Poly1305 unavailable, falling back to ChaCha20Poly1305 for demo.\n"
        )
        sys.stderr.write("This changes nonce length but keeps the envelope flow identical.\n")
    except Exception:
        sys.stderr.write("missing dependency: python 'cryptography' (AEAD)\n")
        sys.stderr.write("install: pip install cryptography\n")
        raise


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def aead_new(key: bytes):
    if AEAD == "xchacha20poly1305":
        return XChaCha20Poly1305(key)
    return ChaCha20Poly1305(key)


def main() -> int:
    print("Enter plaintext to encrypt:")
    plaintext = sys.stdin.readline().rstrip("\n").encode("utf-8")
    if not plaintext:
        sys.stderr.write("plaintext cannot be empty\n")
        return 2

    master_password = getpass("Master password: ")
    if not master_password:
        sys.stderr.write("master password cannot be empty\n")
        return 2

    kdf_salt = os.urandom(16)
    kdf_params = {"n": 2**14, "r": 8, "p": 1, "dk_len": 32}
    master_key = hashlib.scrypt(
        master_password.encode("utf-8"),
        salt=kdf_salt,
        n=kdf_params["n"],
        r=kdf_params["r"],
        p=kdf_params["p"],
        dklen=kdf_params["dk_len"],
    )

    vault_key = os.urandom(32)
    nonce_vault = os.urandom(NonceLen)
    vault_key_enc = aead_new(master_key).encrypt(nonce_vault, vault_key, b"")

    dek = os.urandom(32)

    nonce_dekwrap = os.urandom(NonceLen)
    wrap = aead_new(vault_key)
    ct_dekwrap = wrap.encrypt(nonce_dekwrap, dek, b"")
    enc_dek = nonce_dekwrap + ct_dekwrap

    nonce_payload = os.urandom(NonceLen)
    payload_cipher = aead_new(dek)
    ciphertext = payload_cipher.encrypt(nonce_payload, plaintext, b"")

    out = {
        "aead": AEAD,
        "kdf": {
            "type": "scrypt",
            "salt_b64": b64(kdf_salt),
            "params": kdf_params,
        },
        "vault_key_enc_b64": b64(nonce_vault + vault_key_enc),
        "enc_dek_b64": b64(enc_dek),
        "nonce_payload_b64": b64(nonce_payload),
        "ciphertext_b64": b64(ciphertext),
    }
    with open("demo.json", "w", encoding="utf-8") as handle:
        json.dump(out, handle, indent=2, sort_keys=True)
    with open("demo.jsonc", "w", encoding="utf-8") as handle:
        handle.write("// Demo bundle for crypto_decrypt.py\n")
        handle.write("// This file is JSONC (JSON with comments).\n")
        handle.write("{\n")
        handle.write(f'  "aead": "{out["aead"]}",\n')
        handle.write("  // Base64: nonce_vault || vault_key_enc (vault key wrapped by master key)\n")
        handle.write(f'  "vault_key_enc_b64": "{out["vault_key_enc_b64"]}",\n')
        handle.write("  // Base64: nonce_dek || ct_dek (per-item DEK wrapped by vault key)\n")
        handle.write(f'  "enc_dek_b64": "{out["enc_dek_b64"]}",\n')
        handle.write("  // Base64: payload nonce\n")
        handle.write(f'  "nonce_payload_b64": "{out["nonce_payload_b64"]}",\n')
        handle.write("  // Base64: encrypted payload (AEAD ciphertext)\n")
        handle.write(f'  "ciphertext_b64": "{out["ciphertext_b64"]}",\n')
        handle.write("  // KDF parameters used to derive master key (demo only)\n")
        handle.write('  "kdf": {\n')
        handle.write(f'    "type": "{out["kdf"]["type"]}",\n')
        handle.write(f'    "salt_b64": "{out["kdf"]["salt_b64"]}",\n')
        handle.write(f'    "params": {json.dumps(out["kdf"]["params"], sort_keys=True)}\n')
        handle.write("  }\n")
        handle.write("}\n")
    print("Wrote demo.json and demo.jsonc")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
