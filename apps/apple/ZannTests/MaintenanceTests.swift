import XCTest
import ZannCoreKit
#if os(iOS)
@testable import ZannMobile
#else
@testable import Zann
#endif

private final class PartialExportCore: CoreFacade {
    var entered: (() -> Void)?
    var gate: DispatchSemaphore?
    var fail = false
    override func backupExportFile(path: String, authorization: ExportAuthorizationFfi) throws -> BackupExportReport {
        let report = try super.backupExportFile(path: path, authorization: authorization)
        entered?()
        if let gate, gate.wait(timeout: .now() + 10) != .success { throw CoreError.Service("export test timed out") }
        if fail { throw CoreError.Service("export test failed after writing") }
        return report
    }
}

@MainActor final class MaintenanceTests: XCTestCase {
    private var root: URL!
    private var core: CoreFacade!
    private var model: MaintenanceModel!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        core = try createCore(dbPath: root.appendingPathComponent("local.sqlite").path,
                              keystore: MemoryKeystore(), secretStore: MemorySecretStore())
        _ = try core.seedOfflineFixture(password: "maintenance fixture password")
        _ = try core.itemCreate(create: .init(title: "Offline note", path: "Offline note", typeId: "note",
            payloadJson: #"{"v":1,"typeId":"note","fields":{"text":{"kind":"text","value":"independently readable"}}}"#))
        model = MaintenanceModel(core: core, exportRoot: root.appendingPathComponent("exports"))
        model.sessionOpened()
    }

    override func tearDownWithError() throws {
        model?.invalidate()
        model = nil
        core = nil
        try? FileManager.default.removeItem(at: root)
    }

    private func prepareExport(_ model: MaintenanceModel) async {
        do {
            let operation = try SessionOperationFfi(timeoutMs: 120_000)
            let authorization = try core.authorizeExport(proof: .init(password: "maintenance fixture password", factor: .devicePassword, pin: nil), operation: operation)
            await model.prepareExport(authorization: authorization, operation: operation)
        } catch { XCTFail("Fixture authorization failed: \(describe(error))") }
    }

    func testExportIsPlainVersionedJSONAndPrivateUntilPickerCompletion() async throws {
        await prepareExport(model)
        let export = try XCTUnwrap(model.export)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: export.file)) as? [String: Any])
        XCTAssertEqual(json["version"] as? Int, 1)
        let items = try XCTUnwrap(json["items"] as? [[String: Any]])
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(items[0]["path"] as? String, "Offline note")
        let payload = try XCTUnwrap(items[0]["payload"] as? [String: Any])
        let fields = try XCTUnwrap(payload["fields"] as? [String: [String: Any]])
        XCTAssertEqual(fields["text"]?["value"] as? String, "independently readable")
        for (url, mode) in [(export.directory, 0o700), (export.file, 0o600)] {
            let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
            XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, mode)
        }
        model.finishExport(id: export.id)
        XCTAssertFalse(FileManager.default.fileExists(atPath: export.directory.path))
        model.finishExport(id: export.id) // Dismissal after delegate completion is idempotent.
        XCTAssertNil(model.failure)
    }

    func testFailureAndBackgroundDuringExportRemovePartialOrLateArtifacts() async throws {
        for fail in [false, true] {
            let delayed = PartialExportCore(unsafeFromRawPointer: core.uniffiClonePointer())
            delayed.fail = fail
            let directory = root.appendingPathComponent("delayed-\(fail)")
            let model = MaintenanceModel(core: delayed, exportRoot: directory)
            model.sessionOpened()
            let entered = expectation(description: "export has written private data")
            let gate = DispatchSemaphore(value: 0)
            delayed.entered = { entered.fulfill() }
            delayed.gate = gate
            defer { gate.signal() }
            let preparing = Task { await prepareExport(model) }
            await fulfillment(of: [entered], timeout: 3)
            if fail { model.invalidate() } else { model.dismissed() }
            gate.signal()
            await preparing.value
            XCTAssertNil(model.export)
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty)
            if fail { XCTAssertNotNil(model.failure) }
        }
    }

    func testRelaunchPurgesAbandonedExportAndSnapshotsRetainPendingData() async throws {
        await prepareExport(model)
        let artifact = try XCTUnwrap(model.export)
        let reopened = MaintenanceModel(core: core, exportRoot: root.appendingPathComponent("exports"))
        reopened.sessionOpened()
        XCTAssertFalse(FileManager.default.fileExists(atPath: artifact.file.path))
        await reopened.automaticSnapshot()
        let snapshots = reopened.snapshots
        XCTAssertEqual(snapshots.count, 1)
        await reopened.automaticSnapshot()
        XCTAssertEqual(reopened.snapshots.map(\.path), snapshots.map(\.path))
        await reopened.createSnapshot()
        XCTAssertEqual(reopened.snapshots.count, 2)
        await reopened.verify()
        let verified = try XCTUnwrap(reopened.verification)
        XCTAssertTrue(verified.databaseOk)
        XCTAssertEqual(verified.itemsOk, 1)
        XCTAssertTrue(verified.problems.isEmpty)
        let pending = try core.storageSyncState(storageId: XCTUnwrap(core.currentStorageId())).pendingChanges
        XCTAssertGreaterThan(pending, 0)
        _ = try core.snapshotRestore(path: XCTUnwrap(snapshots.first).path)
        _ = try core.unlock(password: "maintenance fixture password")
        XCTAssertEqual(try core.storageSyncState(storageId: XCTUnwrap(core.currentStorageId())).pendingChanges, pending)
        XCTAssertEqual(try core.verify().itemsOk, 1)
    }

    func testInvalidationRefusesNewSensitiveWorkUntilSessionOpens() async {
        model.invalidate()
        await prepareExport(model)
        await model.verify()
        XCTAssertNil(model.export)
        XCTAssertNil(model.verification)
        model.sessionOpened()
        await prepareExport(model)
        XCTAssertNotNil(model.export)
        model.invalidate()
        XCTAssertNil(model.export)
    }

    func testAutomaticSnapshotFailureIsVisibleAndLeavesOfflineDataReadable() async throws {
        try Data("blocked directory".utf8).write(to: root.appendingPathComponent("snapshots"))
        await model.automaticSnapshot()
        XCTAssertNotNil(model.failure)
        XCTAssertTrue(model.snapshots.isEmpty)
        XCTAssertEqual(try core.verify().itemsOk, 1)
    }

    func testStalePickerCompletionCannotRemoveANewerExportOrReplaceItsError() async throws {
        await prepareExport(model)
        let old = try XCTUnwrap(model.export)
        model.finishExport(id: old.id)
        await prepareExport(model)
        let current = try XCTUnwrap(model.export)
        model.finishExport(id: old.id, failure: CoreError.Service("stale picker error"))
        XCTAssertEqual(model.export?.id, current.id)
        XCTAssertTrue(FileManager.default.fileExists(atPath: current.file.path))
        XCTAssertNil(model.failure)
    }

    #if os(macOS)
    func testNativeExportReplacingAPublicFileKeepsOwnerOnlyPermissions() async throws {
        await prepareExport(model)
        let artifact = try XCTUnwrap(model.export)
        let destination = root.appendingPathComponent("selected.json")
        try Data("old".utf8).write(to: destination)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: destination.path)
        try ExportDestination.copy(source: artifact.file, to: destination)
        let attrs = try FileManager.default.attributesOfItem(atPath: destination.path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        let saved = try Data(contentsOf: destination)
        XCTAssertEqual(saved, try Data(contentsOf: artifact.file))
        XCTAssertNoThrow(try JSONSerialization.jsonObject(with: saved))
    }
    #endif
}
