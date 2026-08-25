# Client compatibility fixtures

Everything in this directory is synthetic test data. The token, password and
key-shaped values are deliberately public and must never be replaced with a
real user config, database or vault export.

The `client-config/v1` corpus characterizes the incompatible legacy readers and
writers covered by MIG-005. Assertions that demonstrate field loss describe the
current migration risk; they are not the contract for config v2 and should be
removed when the shared repository replaces those writers.

The `crypto` corpus is a frozen decrypt/KDF compatibility contract covered by
MIG-004. Encryption uses random nonces, so tests decrypt the recorded envelope
instead of comparing newly encrypted bytes.
