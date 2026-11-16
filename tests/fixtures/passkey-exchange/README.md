# Synthetic external passkey corpus

All credentials are synthetic. The P-256 scalar and public point are the public
RFC 6979 A.2.5 ECDSA test vector; they must never be used for real accounts.
The PKCS#8 DER, COSE private map and export documents were constructed independently
of Zann's serializers, from the wire definitions below. No upstream code was copied.

- [CXF 1.0 PS, March 2026 errata](https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html): header/account/item/passkey, basic-auth and note.
- [Bitwarden exporter JSON schema](https://github.com/bitwarden/sdk-internal/blob/main/crates/bitwarden-exporters/src/json.rs) and [FIDO credential ID encoding](https://github.com/bitwarden/sdk-internal/blob/main/crates/bitwarden-fido/src/lib.rs): UUID and explicit `b64.` forms; PKCS#8 keyValue.
- [KeePassXC passkey exporter](https://github.com/keepassxreboot/keepassxc/blob/develop/src/gui/passkeys/PasskeyExporter.cpp), [attribute names](https://github.com/keepassxreboot/keepassxc/blob/develop/src/core/EntryAttributes.cpp), and [XML writer](https://github.com/keepassxreboot/keepassxc/blob/develop/src/format/KdbxXmlWriter.cpp): `.passkey`, canonical KPEX fields and plaintext XML. History contains a deliberately invalid revoked key and must be ignored.
- [RFC 6979 A.2.5](https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.5): independent public key used to verify every imported assertion.

Unknown creation times in `.passkey` remain absent. CXF integer seconds and
Bitwarden/XML nanoseconds exercise preservation through Zann's namespaced CXF
metadata extension. The COSE fixture is an explicit EC2 private-key codec test;
these manager schemas use PKCS#8, so import never guesses between key encodings.
