import ZannCoreKit

// UniFFI enum payloads otherwise use Swift's reflecting diagnostics. Match
// Rust's redaction so passwords and authorization URLs stay out of UI logs.
extension ConnectActionFfi: CustomDebugStringConvertible {
    public var debugDescription: String { "ConnectAction(<redacted>)" }
}
extension ConnectCompletionFfi: CustomDebugStringConvertible {
    public var debugDescription: String { "ConnectCompletion(<redacted>)" }
}
extension ConnectEffectFfi: CustomDebugStringConvertible {
    public var debugDescription: String { "ConnectEffect(<redacted>)" }
}
extension ConnectSnapshotFfi: CustomDebugStringConvertible {
    public var debugDescription: String { "ConnectSnapshot(<redacted>)" }
}
extension ConnectStageFfi: CustomDebugStringConvertible {
    public var debugDescription: String { "ConnectStage(<redacted>)" }
}
