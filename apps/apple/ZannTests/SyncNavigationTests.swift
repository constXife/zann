import XCTest
import ZannCoreKit
@testable import Zann

/// The second vault is a UI projection fixture; native storage/key isolation
/// is exercised separately by StorageContextTests and the Rust context tests.
private final class NavigationCore: UXDelayedCore {
    let extra = VaultSummaryFfi(id: "fixture-team", name: "Team", scope: .shared, isDefault: false, itemCount: 0)
    private let stateLock = NSLock()
    private var virtualVault: String?
    private var pageDelay: (() throws -> Void)?
    var followCalls = 0

    func delayNextPage(_ delay: @escaping () throws -> Void) {
        stateLock.lock()
        pageDelay = delay
        stateLock.unlock()
    }
    override func currentVaultId() -> String? {
        stateLock.lock()
        let virtual = virtualVault
        stateLock.unlock()
        return virtual ?? super.currentVaultId()
    }
    override func listVaults() throws -> [VaultSummaryFfi] {
        try super.listVaults() + [extra]
    }
    override func setCurrentVault(id: String) throws -> VaultStatus {
        stateLock.lock()
        virtualVault = id == extra.id ? id : nil
        stateLock.unlock()
        return id == extra.id ? VaultStatus(unlocked: true) : try super.setCurrentVault(id: id)
    }
    override func itemsList(filter: ItemsFilter, page: Page) throws -> ItemPage {
        let result = currentVaultId() == extra.id
            ? ItemPage(items: [], nextCursor: nil, totalCount: 0, counts: .init(all: 0, trash: 0, byType: []))
            : try super.itemsList(filter: filter, page: page)
        stateLock.lock()
        let delay = pageDelay
        pageDelay = nil
        stateLock.unlock()
        try delay?()
        return result
    }
    override func followPreferredStorage() throws {
        followCalls += 1
        try super.followPreferredStorage()
    }
}

@MainActor final class SyncNavigationTests: XCTestCase {
    private var directory: URL!
    private var core: NavigationCore!
    private var remote: String!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let database = directory.appendingPathComponent("local.sqlite")
        let real = try createCore(dbPath: database.path, keystore: MemoryKeystore(), secretStore: MemorySecretStore())
        _ = try real.initializeMasterPassword(password: "fixture master password")
        remote = try seedStorageContext(database: database)
        core = NavigationCore(unsafeFromRawPointer: real.uniffiClonePointer())
        _ = try core.itemCreate(create: .init(title: "Local note", path: "Local note", typeId: "note",
            payloadJson: #"{"v":1,"typeId":"note","fields":{"text":{"kind":"text","value":"fixture"}}}"#))
    }
    override func tearDownWithError() throws {
        core?.syncGate?.signal()
        core = nil
        try? FileManager.default.removeItem(at: directory)
    }
    private func makeModel(follow: Bool = false) throws -> VaultModel {
        VaultModel(core: core, contents: try VaultModel.load(core), strings: Strings(language: "en"), followAfterSync: follow)
    }
    private func checkStorageSwitch(failing: Bool) async throws {
        let model = try makeModel()
        let local = model.storageID
        let started = expectation(description: "sync started on original storage")
        let gate = DispatchSemaphore(value: 0)
        core.syncGate = gate
        core.syncChanges = 1
        core.syncFailure = failing ? .Service("fixture sync failure") : nil
        core.onSyncStorage = { target in
            XCTAssertEqual(target, local)
            started.fulfill()
        }
        defer { gate.signal() }
        let sync = Task { await model.sync() }
        await fulfillment(of: [started], timeout: 2)
        await model.selectStorage(remote)
        XCTAssertEqual(model.storageID, remote, "navigation must finish before the network gate opens")
        XCTAssertEqual(core.currentStorageId(), remote)
        XCTAssertFalse(model.syncing, "another server's progress must not follow the picker")
        XCTAssertEqual(model.syncingStorageID, local)
        XCTAssertTrue(model.visibleItems.isEmpty)
        gate.signal()
        await sync.value
        XCTAssertEqual(model.storageID, remote)
        XCTAssertTrue(model.visibleItems.isEmpty)
        XCTAssertNil(model.syncError, "old server errors must not appear on the new server")
        XCTAssertNil(model.syncingStorageID)
    }
    func testStorageSwitchDoesNotWaitForSyncOrRestoreItsOldContents() async throws {
        try await checkStorageSwitch(failing: false)
    }
    func testOldServerFailureDoesNotAffectNewServer() async throws {
        try await checkStorageSwitch(failing: true)
    }
    func testVaultSwitchDuringFirstSyncWinsOverAutomaticFollowing() async throws {
        let model = try makeModel(follow: true)
        let started = expectation(description: "first sync started")
        let gate = DispatchSemaphore(value: 0)
        core.syncGate = gate
        core.syncChanges = 1
        core.onSync = { started.fulfill() }
        defer { gate.signal() }
        let sync = Task { await model.sync() }
        await fulfillment(of: [started], timeout: 2)
        await model.selectVault(core.extra.id)
        XCTAssertEqual(model.vaultID, core.extra.id)
        XCTAssertTrue(model.syncing, "same server still owns this sync")
        gate.signal()
        await sync.value
        XCTAssertEqual(model.vaultID, core.extra.id)
        XCTAssertTrue(model.visibleItems.isEmpty)
        XCTAssertEqual(core.followCalls, 0, "explicit navigation cancels the automatic handoff")
    }
    func testLatePageCannotOverwriteNavigationAwayAndBack() async throws {
        let model = try makeModel()
        let local = model.storageID
        let read = expectation(description: "post-sync page snapshot captured")
        let gate = DispatchSemaphore(value: 0)
        core.syncChanges = 1
        core.delayNextPage {
            read.fulfill()
            guard gate.wait(timeout: .now() + 5) == .success else { throw CoreError.Service("fixture page timeout") }
        }
        defer { gate.signal() }
        let sync = Task { await model.sync() }
        await fulfillment(of: [read], timeout: 2)
        await model.selectStorage(remote)
        await model.selectStorage(local)
        model.startCreating(typeID: "note")
        try XCTUnwrap(model.editor).name = "Newer note"
        await model.saveEditor()
        XCTAssertEqual(model.visibleItems.count, 2)
        gate.signal()
        await sync.value
        XCTAssertEqual(model.storageID, local)
        XCTAssertEqual(Set(model.visibleItems.map(\.title)), ["Local note", "Newer note"])
    }
}
