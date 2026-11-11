// Linked against the host libzann_ffi by the `ffi-native-targets` CI job:
// proves the generated Swift bindings compile and reach the Rust exports.

let schemas = itemTypeSchemas()
precondition(!schemas.isEmpty, "item type schemas must be exported")

let defaults = devicePreferencesDefault()
precondition(defaults == devicePreferencesDefault(), "defaults must be stable")

precondition(
    normalizeServerUrl(value: "  https://zann.example  ") == "https://zann.example",
    "server URL normalization must cross the FFI boundary"
)

print("zann-ffi Swift bindings: \(schemas.count) item types")
