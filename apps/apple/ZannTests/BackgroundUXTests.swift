import XCTest
import ZannCoreKit
@testable import Zann

/// Delays effects around a real temporary core; no real server or Keychain.
class UXDelayedCore: CoreFacade {
    var syncGate: DispatchSemaphore?
    var onSync: (() -> Void)?
    var onSyncStorage: ((String?) -> Void)?
    var syncChanges: UInt32 = 0
    var syncFailure: CoreError?
    var slowItemID: String?
    var itemGate: DispatchSemaphore?
    var onItemRead: (() -> Void)?

    convenience init(wrapping core: CoreFacade) {
        self.init(unsafeFromRawPointer: core.uniffiClonePointer())
    }

    override func storageSyncState(storageId: String) throws -> StorageSyncStateFfi {
        StorageSyncStateFfi(link: .connected, serverUrl: "https://fixture.example.test",
                            pendingChanges: 0, lastSyncedAt: nil)
    }

    override func remoteSync(storageId: String?) throws -> SyncOutcomeFfi {
        onSync?()
        onSyncStorage?(storageId)
        if let syncGate, syncGate.wait(timeout: .now() + 5) != .success {
            throw CoreError.Service("fixture sync gate timed out")
        }
        if let syncFailure { throw syncFailure }
        return SyncOutcomeFfi(status: "completed", vaultsReconciled: 0, pagesCommitted: 0, changesCommitted: syncChanges)
    }

    override func itemDetail(id: String, operation: SessionOperationFfi) throws -> ItemDetailViewFfi {
        if id == slowItemID {
            onItemRead?()
            if let itemGate, itemGate.wait(timeout: .now() + 5) != .success {
                throw CoreError.Service("fixture item gate timed out")
            }
        }
        return try super.itemDetail(id: id, operation: operation)
    }
}

@MainActor final class BackgroundUXTests: XCTestCase {
    private var directory: URL!
    private var core: UXDelayedCore!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let real = try createCore(dbPath: directory.appendingPathComponent("local.sqlite").path,
                                  keystore: MemoryKeystore(), secretStore: MemorySecretStore())
        _ = try real.initializeMasterPassword(password: "fixture master password")
        core = UXDelayedCore(wrapping: real)
        for title in ["First", "Second"] {
            _ = try core.itemCreate(create: ItemCreate(title: title, path: title, typeId: "login",
                payloadJson: #"{"v":1,"typeId":"login","fields":{"password":{"kind":"password","value":"fixture-value"}}}"#))
        }
    }

    override func tearDownWithError() throws {
        core?.syncGate?.signal()
        core?.itemGate?.signal()
        core = nil
        try? FileManager.default.removeItem(at: directory)
    }

    func testFirstConnectionOpensCachedUIWhileSyncIsStillWaiting() async throws {
        let started = expectation(description: "background sync started")
        let gate = DispatchSemaphore(value: 0)
        core.syncGate = gate
        core.onSync = { started.fulfill() }
        defer { gate.signal() }
        _ = try core.lock()
        let core = try XCTUnwrap(core)
        let app = AppModel(opening: { (core, MemoryKeystore()) },
            preferences: { PreferencesFile(url: self.directory.appendingPathComponent("prefs.json")) },
            systemLanguage: "en", openBrowser: { _ in })
        app.startConnecting()
        app.connected(.init(hasPersonalKeys: true))
        let unlock = Task { await app.submit(password: "fixture master password", mode: .unlock) }
        await fulfillment(of: [started], timeout: 4)
        XCTAssertEqual(app.screen, .vault, "network sync must not hold the password screen")
        XCTAssertFalse(app.busy)
        let vault = try XCTUnwrap(app.vault)
        XCTAssertTrue(vault.syncing)
        XCTAssertFalse(vault.switching)
        vault.query = "First"
        XCTAssertEqual(vault.visibleItems.map(\.title), ["First"])
        vault.startCreating(typeID: "note")
        XCTAssertNotNil(vault.editor, "the workspace remains usable during sync")
        await unlock.value
        let finishing = Task { await vault.sync() }
        await Task.yield()
        gate.signal()
        await finishing.value
        XCTAssertNil(vault.syncError)
        vault.cancelEditing()
        await app.lock()
    }

    func testReplacementKeepsPreviousCardWithoutEnablingItsActions() async throws {
        let model = VaultModel(core: core, contents: try VaultModel.load(core), strings: Strings(language: "en"))
        let first = try XCTUnwrap(model.visibleItems.first { $0.title == "First" })
        let second = try XCTUnwrap(model.visibleItems.first { $0.title == "Second" })
        model.select(first.id)
        for _ in 0..<100 where model.detailLoading { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(model.detail?.id, first.id)
        XCTAssertTrue(model.canEdit)
        let started = expectation(description: "replacement read started")
        let gate = DispatchSemaphore(value: 0)
        core.slowItemID = second.id
        core.itemGate = gate
        core.onItemRead = { started.fulfill() }
        defer { gate.signal() }
        model.select(second.id)
        await fulfillment(of: [started], timeout: 2)
        XCTAssertTrue(model.detailLoading)
        XCTAssertEqual(model.detail?.id, first.id, "the panel must not turn into a spinner")
        XCTAssertFalse(model.canEdit, "the retained card must not edit the wrong selection")
        await model.startEditing()
        XCTAssertNil(model.editor)
        gate.signal()
        for _ in 0..<100 where model.detailLoading { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(model.detail?.id, second.id)
        XCTAssertTrue(model.canEdit)
        model.select(nil)
        XCTAssertNil(model.detail)
        XCTAssertFalse(model.detailLoading)
    }
}
