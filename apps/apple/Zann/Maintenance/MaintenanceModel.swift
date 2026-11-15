import Foundation
import ZannCoreKit

/// Native execution and presentation only. Backup format, snapshot cadence,
/// retention and integrity checks belong to the existing Rust owners.
@MainActor
final class MaintenanceModel: ObservableObject {
    @Published private(set) var busy = false
    @Published private(set) var failure: Error?
    @Published private(set) var snapshots: [SnapshotFfi] = []
    @Published private(set) var verification: VerifyReportFfi?
    @Published private(set) var export: TemporaryExport?
    let core: CoreFacade
    let encrypted: EncryptedBackupModel
    let passkeys: PasskeyExchangeModel
    private var exportOperation: SessionOperationFfi?
    private let exportRoot: URL
    private var generation = 0
    private var sensitiveOperationsAllowed = false

    convenience init(core: CoreFacade) {
        self.init(core: core, exportRoot: FileManager.default.temporaryDirectory.appendingPathComponent("zann-exports"))
    }

    init(core: CoreFacade, exportRoot: URL) {
        self.core = core
        self.exportRoot = exportRoot
        self.passkeys = PasskeyExchangeModel(core: core, root: exportRoot.appendingPathComponent("passkeys"))
        self.encrypted = EncryptedBackupModel(core: core, root: exportRoot.appendingPathComponent("encrypted"))
        let cleanup = Result { try TemporaryExport.purge(exportRoot) }
        if case .failure(let error) = cleanup { failure = error }
    }

    func automaticSnapshot() async { await snapshot(automatic: true) }
    func createSnapshot() async { await snapshot(automatic: false) }

    func sessionOpened() { sensitiveOperationsAllowed = true }

    private func snapshot(automatic: Bool) async {
        guard !busy else { return }
        busy = true
        if !automatic { failure = nil }
        defer { busy = false }
        let core = core
        let result = await BlockingCore.run {
            Result { () -> [SnapshotFfi] in
                if automatic {
                    _ = try core.snapshotCreateIfDue(maxAgeHours: autoSnapshotMaxAgeHours(), retention: nil)
                } else {
                    _ = try core.snapshotCreate(retention: nil)
                }
                return try core.snapshotList()
            }
        }
        switch result {
        case .success(let rows): snapshots = rows
        case .failure(let error): failure = error
        }
    }

    func verify() async {
        guard !busy, sensitiveOperationsAllowed else { return }
        busy = true
        failure = nil
        verification = nil
        let epoch = generation
        defer { busy = false }
        let core = core
        let result = await BlockingCore.run { Result { try core.verify() } }
        guard epoch == generation else { return }
        switch result {
        case .success(let report): verification = report
        case .failure(let error): failure = error
        }
    }

    func prepareExport(authorization: ExportAuthorizationFfi, operation: SessionOperationFfi) async {
        guard !busy, sensitiveOperationsAllowed, export == nil else { return }
        busy = true
        failure = nil
        let epoch = generation
        defer { busy = false }
        let core = core
        let root = exportRoot
        exportOperation = operation
        defer { exportOperation = nil }
        let result = await BlockingCore.run { Result { try TemporaryExport.prepare(core: core, root: root, authorization: authorization) } }
        switch result {
        case .success(let artifact):
            if epoch == generation { export = artifact }
            else { remove(artifact) }
        case .failure(let error): failure = error
        }
    }

    /// File picker success, cancel and dismissal all release the same lease.
    func finishExport(id: UUID, failure: Error? = nil) {
        guard export?.id == id else { return }
        clearExport(failure)
    }

    private func clearExport(_ pickerFailure: Error? = nil) {
        if let pickerFailure { failure = pickerFailure }
        guard let artifact = export else { return }
        export = nil
        remove(artifact)
    }

    /// Lock/background invalidates a late export and clears sensitive reports.
    func invalidate() {
        sensitiveOperationsAllowed = false
        dismissed()
    }

    /// Leaving Settings also invalidates work that has not opened a picker yet.
    func dismissed() {
        encrypted.cancel()
        passkeys.cancel()
        exportOperation?.cancel()
        generation += 1
        verification = nil
        clearExport()
    }

    private func remove(_ artifact: TemporaryExport) {
        if case .failure(let error) = Result(catching: artifact.remove) {
            if let original = failure { failure = TemporaryExport.CleanupFailure(original: original, cleanup: error) }
            else { failure = error }
        }
    }
}
