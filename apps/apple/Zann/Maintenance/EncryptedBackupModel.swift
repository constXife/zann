import Foundation
import ZannCoreKit

/// Native execution only; format, factors, admission and preflight belong to Rust.
@MainActor final class EncryptedBackupModel: ObservableObject {
    @Published private(set) var busy = false
    @Published private(set) var failure: Error?
    @Published private(set) var recipients: [BackupRecipientSummaryFfi] = []
    @Published private(set) var inspection: BackupInspectionFfi?
    @Published private(set) var imported: BackupImportReport?
    @Published private(set) var artifact: TemporaryExport?
    @Published private(set) var capabilities: BackupCapabilitiesFfi?
    var canRestore: Bool { handle != nil && inspection != nil }
    var canExport: Bool { handle != nil && inspection == nil && artifact == nil }
    @Published private(set) var targets: [StorageSummaryFfi] = []
    private let core: CoreFacade
    private let root: URL
    private var handle: BackupHandleFfi?
    private var operation: SessionOperationFfi?
    private var source: ScopedBackupURL?
    private var generation = 0

    init(core: CoreFacade, root: URL) { self.core = core; self.root = root }

    func begin() async {
        guard !busy else { return }
        cancel()
        do {
            let pending = try SessionOperationFfi(timeoutMs: 600_000)
            operation = pending
            let core = core
            await run {
                let caps = try core.backupCapabilities()
                return .begun(try core.backupBegin(operation: pending), caps)
            }
        } catch { failure = error }
    }
    func add(_ recipient: BackupRecipientFfi) async {
        guard let handle, !busy else { return }
        let core = core
        await run { .added(try core.backupAddRecipient(handle: handle, recipient: recipient)) }
    }
    func export() async {
        guard let handle, !busy else { return }
        self.handle = nil
        let core = core, root = root
        await run { .exported(try TemporaryExport.prepareEncrypted(core: core, root: root, handle: handle)) }
    }
    func chooseSource(_ url: URL) async {
        guard !busy else { return }
        cancel()
        let lease = ScopedBackupURL(url)
        source = lease
        let core = core
        await run { .recipients(try core.backupEncryptedRecipients(path: lease.url.path)) }
    }
    func open(slot: UInt32, recipient: BackupRecipientFfi) async {
        guard let source, !busy else { return }
        do {
            let pending = try SessionOperationFfi(timeoutMs: 600_000)
            operation = pending
            let core = core
            await run {
                let handle = try core.backupOpenEncrypted(path: source.url.path, slot: slot, recipient: recipient, operation: pending)
                do {
                    let inspection = try core.backupInspectEncrypted(handle: handle)
                    return .opened(handle, inspection, try core.listStorages())
                } catch {
                    let original = error
                    do { try core.backupCancel(handle: handle) }
                    catch { throw TemporaryExport.CleanupFailure(original: original, cleanup: error) }
                    throw original
                }
            }
        } catch { failure = error }
    }
    func restore(sourceStorage: String, targetStorage: String) async {
        guard let handle, !busy else { return }
        self.handle = nil
        let core = core
        await run { .imported(try core.backupImportEncrypted(handle: handle, sourceStorageId: sourceStorage,
            options: .init(targetStorageId: targetStorage))) }
    }
    func cancel() {
        generation += 1
        operation?.cancel(); operation = nil
        if let handle {
            if case .failure(let error) = Result(catching: { try core.backupCancel(handle: handle) }) { failure = error }
        }
        handle = nil
        source = nil
        if let artifact { remove(artifact) }
        artifact = nil
        recipients = []; inspection = nil; imported = nil; targets = []; capabilities = nil; busy = false
    }
    func finishExport(_ error: Error?) {
        if let error { failure = error }
        if let artifact { remove(artifact) }
        artifact = nil
    }
    private func remove(_ value: TemporaryExport) {
        if case .failure(let error) = Result(catching: value.remove) {
            if let original = failure { failure = TemporaryExport.CleanupFailure(original: original, cleanup: error) }
            else { failure = error }
        }
    }
    private enum Effect {
        case begun(BackupHandleFfi, BackupCapabilitiesFfi)
        case added(BackupRecipientSummaryFfi)
        case exported(TemporaryExport)
        case recipients([BackupRecipientSummaryFfi])
        case opened(BackupHandleFfi, BackupInspectionFfi, [StorageSummaryFfi])
        case imported(BackupImportReport)
    }
    private func run(_ work: @escaping @Sendable () throws -> Effect) async {
        busy = true; failure = nil
        let epoch = generation
        let result = await BlockingCore.run { Result(catching: work) }
        guard epoch == generation else {
            if case .success(let effect) = result {
                switch effect {
                case .exported(let artifact): remove(artifact)
                case .begun(let handle, _), .opened(let handle, _, _):
                    if case .failure(let error) = Result(catching: { try core.backupCancel(handle: handle) }) { failure = error }
                default: break
                }
            }
            return
        }
        busy = false
        switch result {
        case .failure(let error): failure = error
        case .success(let effect):
            switch effect {
            case .begun(let value, let caps): handle = value; capabilities = caps
            case .added(let value): recipients.append(value)
            case .exported(let value): artifact = value; handle = nil
            case .recipients(let rows): recipients = rows
            case .opened(let value, let report, let storages):
                handle = value; inspection = report; targets = storages
            case .imported(let value): imported = value; handle = nil
            }
        }
    }
}

/// Holds the native document-picker grant for every authenticated parser pass.
private final class ScopedBackupURL: @unchecked Sendable {
    let url: URL
    private let scoped: Bool
    init(_ url: URL) { self.url = url; scoped = url.startAccessingSecurityScopedResource() }
    deinit { if scoped { url.stopAccessingSecurityScopedResource() } }
}
