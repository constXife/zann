# Client compatibility fixtures

Everything in this directory is synthetic test data. The token, password and
key-shaped values are deliberately public and must never be replaced with a
real user config, database or vault export.

The `client-config/v1` corpus characterizes the incompatible legacy readers and
formats. The incompatible Tauri writer is retired; the corpus remains input
for the canonical one-way Config v2 migration tests, not an active writer
contract.

The `crypto` corpus is the frozen decrypt/KDF compatibility contract retained
after MIG-004 retirement (ADR 0009). Encryption uses random nonces, so tests decrypt the recorded envelope
instead of comparing newly encrypted bytes.
