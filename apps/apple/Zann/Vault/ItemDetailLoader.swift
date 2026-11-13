import Foundation
import ZannCoreKit

/// Owns one replaceable card read. Cancellation reaches the Rust operation,
/// including while SQLite is waiting; cancelled results never reach the view.
@MainActor
final class ItemDetailLoader {
    typealias Read = @Sendable (String, SessionOperationFfi) throws -> ItemDetailViewFfi
    private let read: Read
    private var operation: SessionOperationFfi?
    private var task: Task<Void, Never>?

    init(core: CoreFacade) {
        read = { try core.itemDetail(id: $0, operation: $1) }
    }

    init(read: @escaping Read) { self.read = read }

    deinit {
        operation?.cancel()
        task?.cancel()
    }

    func cancel() {
        operation?.cancel()
        task?.cancel()
        operation = nil
        task = nil
    }

    func load(_ id: String, receive: @escaping (Result<ItemDetailViewFfi, Error>) -> Void) {
        cancel()
        let operation: SessionOperationFfi
        do {
            operation = try SessionOperationFfi(timeoutMs: 10_000)
        } catch {
            receive(.failure(error))
            return
        }
        self.operation = operation
        let read = read
        task = Task { [weak self] in
            guard !Task.isCancelled else { return }
            let result = await withTaskCancellationHandler {
                await Task.detached(priority: .userInitiated) {
                    Result { try read(id, operation) }
                }.value
            } onCancel: {
                operation.cancel()
            }
            guard !Task.isCancelled, let self else { return }
            if case .failure(CoreError.Cancelled) = result {
                self.operation = nil
                self.task = nil
                return
            }
            self.operation = nil
            self.task = nil
            receive(result)
        }
    }
}
