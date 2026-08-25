## Summary

(what and why)

## Testing

- [ ] cargo test
- [ ] cargo fmt
- [ ] cargo clippy --all-targets --all-features
- [ ] just architecture-check (for client/shared-contract changes)

(others, if applicable)

## Client architecture

(Select N/A or complete every applicable item.)

- [ ] N/A — this PR does not change a shared client capability or contract
- [ ] Shared behavior has one canonical owner; CLI/Tauri/COSMIC only adapt it
- [ ] Every affected consumer is covered by a contract/conformance test
- [ ] Config, credential, protocol, or persisted-state changes include a migration/compatibility path
- [ ] Any temporary architecture exception links to an issue/ADR with a removal condition

## Risk / Notes

(if auth/crypto/db/schema/network changes, describe briefly)
