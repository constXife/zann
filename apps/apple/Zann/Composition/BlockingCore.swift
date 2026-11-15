import Dispatch

/// Synchronous FFI can wait for network, storage or native prompts. Keep that
/// work outside Swift's cooperative executor so other async effects can resume.
/// Callers retain operation cancellation/admission; this await finishes only
/// after the synchronous call returns, including during background locking.
enum BlockingCore {
    static func run<Value>(_ work: @escaping @Sendable () -> Value) async -> Value {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: work())
            }
        }
    }
}
