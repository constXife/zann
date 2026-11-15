import Foundation

@MainActor
protocol ClipboardSink: AnyObject {
    var changeCount: Int { get }
    func write(_ value: String, expiration: Date?)
    func clear()
}

/// One clipboard write lease. Timers can clear only their own generation;
/// the OS expiration on iOS remains effective while the process is suspended.
@MainActor
final class ClipboardController {
    private let sink: ClipboardSink
    private var ownedChangeCount: Int?
    private var generation = 0
    private var expiration: Date?
    private var timer: Task<Void, Never>?

    init(sink: ClipboardSink) { self.sink = sink }
    deinit { timer?.cancel() }

    func copy(_ value: String, clearAfter seconds: UInt32, onlyIfUnchanged: Bool) {
        timer?.cancel()
        generation += 1
        let started = generation
        expiration = seconds > 0 ? Date().addingTimeInterval(TimeInterval(seconds)) : nil
        sink.write(value, expiration: expiration)
        let changeCount = sink.changeCount
        ownedChangeCount = changeCount
        guard seconds > 0 else { return }
        timer = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000)
            guard let self, !Task.isCancelled, self.generation == started else { return }
            if !onlyIfUnchanged || self.sink.changeCount == changeCount { self.clearOwned() }
        }
    }

    func clearOwned() {
        timer?.cancel()
        if let ownedChangeCount, sink.changeCount == ownedChangeCount { sink.clear() }
        ownedChangeCount = nil
        expiration = nil
        generation += 1
    }

    func reconcile(now: Date = Date()) {
        if let expiration, now >= expiration { clearOwned() }
    }
}
