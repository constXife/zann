import Foundation
import ZannCoreKit

/// At most one UI reload and one latest notice, regardless of pull-page rate.
/// The callback carries no item data and never waits for the main actor.
final class SyncCommitRelay: SyncCommitObserver, @unchecked Sendable {
    private let lock = NSLock()
    private var latest: SyncCommitFfi?
    private var task: Task<Void, Never>?
    private var stopped = false
    private let receive: @MainActor (SyncCommitFfi) async -> Void

    init(receive: @escaping @MainActor (SyncCommitFfi) async -> Void) {
        self.receive = receive
    }

    func committed(update: SyncCommitFfi) {
        lock.lock()
        defer { lock.unlock() }
        guard !stopped else { return }
        latest = update
        if task == nil {
            task = Task { @MainActor in
                while let notice = self.take() { await self.receive(notice) }
            }
        }
    }

    private func take() -> SyncCommitFfi? {
        lock.lock()
        defer { lock.unlock() }
        let notice = latest
        latest = nil
        if notice == nil { task = nil }
        return notice
    }

    private func currentTask() -> Task<Void, Never>? {
        lock.lock()
        defer { lock.unlock() }
        return task
    }

    /// Called after the blocking sync returns, when no more callbacks can arrive.
    func finish() async { await currentTask()?.value }

    func cancel() {
        lock.lock()
        stopped = true
        latest = nil
        lock.unlock()
    }
}
