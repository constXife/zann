import SwiftUI

/// Explicit, temporary native reveal state shared by detail and editor.
/// A cancelled timer cannot mask a later reveal of the same field.
@MainActor
final class FieldRevealState: ObservableObject {
    @Published private(set) var revealed: Set<Int> = []
    private var tasks: [Int: Task<Void, Never>] = [:]
    private var generation = 0

    deinit { tasks.values.forEach { $0.cancel() } }

    func toggle(_ index: Int, seconds: UInt32) {
        tasks[index]?.cancel()
        tasks[index] = nil
        if revealed.remove(index) != nil { return }
        revealed.insert(index)
        guard seconds > 0 else { return }
        let started = generation
        tasks[index] = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000)
            guard !Task.isCancelled, let self, self.generation == started else { return }
            self.revealed.remove(index)
            self.tasks[index] = nil
        }
    }

    func reset() {
        generation += 1
        tasks.values.forEach { $0.cancel() }
        tasks.removeAll()
        revealed.removeAll()
    }
}
