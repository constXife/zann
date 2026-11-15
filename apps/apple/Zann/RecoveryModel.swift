import Foundation
import ZannCoreKit

/// Native I/O and observable results; scope/consent/source checks live in Rust.
@MainActor
final class RecoveryModel: ObservableObject {
    @Published private(set) var accounts: [SetupAccountFfi] = []
    @Published private(set) var preview: RecoveryPreviewFfi?
    @Published private(set) var busy = false
    @Published private(set) var error: String?
    @Published private(set) var snapshotPath: String?
    @Published private(set) var selected: SetupAccountFfi?
    private let core: CoreFacade
    private let strings: Strings
    private let stateChanged: () -> Void
    private let completed: (RecoveryOutcomeFfi) -> Void

    init(core: CoreFacade, strings: Strings, stateChanged: @escaping () -> Void, completed: @escaping (RecoveryOutcomeFfi) -> Void) { self.core = core; self.strings = strings; self.completed = completed; self.stateChanged = stateChanged }

    func reload() async {
        let core = core
        await run {
            let accounts = try await BlockingCore.run { Result { try core.setupAccounts() } }.get()
            self.accounts = accounts
        }
    }
    func prepare(_ account: SetupAccountFfi?) async {
        let core = core
        await run {
            self.selected = account
            let id = account?.storageId
            self.preview = try await BlockingCore.run { Result { try core.prepareLocalRecovery(storageId: id) } }.get()
        }
    }
    func cancel() async {
        guard let id = preview?.id, !busy else { return }
        let core = core
        await run { try await BlockingCore.run { Result { try core.cancelLocalRecovery(id: id) } }.get(); self.preview = nil }
    }
    func confirm(discardUnsent: Bool) async {
        guard let id = preview?.id else { return }
        let core = core
        await run {
            let result = try await BlockingCore.run { Result { try core.confirmLocalRecovery(id: id, discardUnsent: discardUnsent) } }.get()
            self.completed(result)
            self.snapshotPath = result.snapshotPath
            self.preview = nil
            self.accounts = try await BlockingCore.run { Result { try core.setupAccounts() } }.get()
        }
    }
    private func run(_ work: () async throws -> Void) async {
        guard !busy else { return }
        busy = true; error = nil
        defer { busy = false; stateChanged() }
        do { try await work() } catch { self.error = strings.message(for: error) }
    }
}
