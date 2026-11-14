# Frozen v1 crypto corpus

All keys, passwords, tokens and peppers in these files are synthetic public
test data. Never replace them with credentials from a real installation.

| Fixture | Contract exercised |
| --- | --- |
| `v1_local_vault.json` | Original ASCII KDF, vault-key wrap and payload envelope |
| `v1_passwords.json` | NFC/NFD KDF equivalence, peppered password hash, opaque service-token hash and KDF fingerprint |
| `v1_rotation.json` | Rotation-candidate AAD, context separation and envelope |
| `v1_device_unlock.json` | DWK master-key wrap and FIDO2 HMAC-output derivation |

`zann-crypto` compatibility tests and `zann-keystore` compatibility tests read
these committed bytes. Tests must never regenerate their own expected values.
The device vectors exercise the production derivation without physical hardware.
Canonical backup round-trips remain in their owning client/server suites.

For an explicitly reviewed Pre-GA format change, regenerate the three added
fixtures from the repository root with:

```sh
cargo run -p zann-crypto --example regenerate_v1_fixtures
```

This uses synthetic constants and fresh AEAD nonces. It deliberately leaves
`v1_local_vault.json` untouched so existing ASCII/framing/AAD compatibility
continues to be tested. Review every changed expected value; regeneration is
never a way to silence an unexplained test failure. Follow
[ADR 0009](../../../docs/adr/0009-crypto-format-lifecycle.md) and the
[NFC cutover gate](../../../docs/migrations/crypto-v1-nfc.md) before release.
