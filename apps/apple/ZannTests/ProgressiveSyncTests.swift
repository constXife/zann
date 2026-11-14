import XCTest
import ZannCoreKit
@testable import Zann

/// Holds the network between durable catalog/page publications.
private final class ProgressiveCore: UXDelayedCore {
    let catalogGate = DispatchSemaphore(value: 0)
    let pageGate = DispatchSemaphore(value: 0)
    let finishGate = DispatchSemaphore(value: 0)
    var failAfterPage = false
    var catalogReadGate: DispatchSemaphore?
    var onCatalogRead: (() -> Void)?
    private let stateLock = NSLock()
    private var stage = 0
    var fixtureStorageID: String? { super.currentStorageId() }

    private func currentStage() -> Int {
        stateLock.lock(); defer { stateLock.unlock() }
        return stage
    }
    private func publish(_ stage: Int) {
        stateLock.lock(); self.stage = stage; stateLock.unlock()
    }
    override func currentStorageId() -> String? { currentStage() == 0 ? nil : super.currentStorageId() }
    override func currentVaultId() -> String? { currentStage() == 0 ? nil : super.currentVaultId() }
    override func listStorages() throws -> [StorageSummaryFfi] {
        guard currentStage() != 0 else { return [] }
        let storages = try super.listStorages()
        if let gate = catalogReadGate {
            catalogReadGate = nil
            onCatalogRead?()
            try wait(gate)
        }
        return storages
    }
    override func listVaults() throws -> [VaultSummaryFfi] { currentStage() == 0 ? [] : try super.listVaults() }
    override func appStatus() throws -> AppStatusFfi {
        var status = try super.appStatus(); status.serverConnected = true; return status
    }
    override func storageSyncState(storageId: String) throws -> StorageSyncStateFfi {
        .init(link: .connected, serverUrl: "https://fixture.example.test", pendingChanges: 0,
            lastSyncedAt: currentStage() < 2 ? nil : "2026-11-13T00:00:00Z")
    }
    override func itemsList(filter: ItemsFilter, page: Page) throws -> ItemPage {
        let stage = currentStage()
        let actual = try super.itemsList(filter: filter, page: page)
        let available = stage < 2 ? [] : stage == 2 ? actual.items.filter { $0.title == "First" } : actual.items
        return ItemPage(items: available, nextCursor: nil, totalCount: UInt64(available.count),
            counts: .init(all: UInt64(available.count), trash: 0, byType: []))
    }
    private func wait(_ gate: DispatchSemaphore) throws {
        guard gate.wait(timeout: .now() + 10) == .success else { throw CoreError.Service("progress fixture timed out") }
    }
    override func remoteSync(storageId: String?, progress: SyncCommitObserver?) throws -> SyncOutcomeFfi {
        let id = try XCTUnwrap(super.currentStorageId())
        publish(1)
        progress?.committed(update: .init(storageId: id, phase: .catalog, pagesCommitted: 0, changesCommitted: 0))
        try wait(catalogGate)
        publish(2)
        progress?.committed(update: .init(storageId: id, phase: .page, pagesCommitted: 1, changesCommitted: 1))
        try wait(pageGate)
        if failAfterPage { throw CoreError.Service("later page failed") }
        publish(3)
        progress?.committed(update: .init(storageId: id, phase: .page, pagesCommitted: 2, changesCommitted: 2))
        try wait(finishGate)
        return .init(status: "completed", vaultsReconciled: 1, pagesCommitted: 2, changesCommitted: 2)
    }
    func release() { catalogGate.signal(); pageGate.signal(); finishGate.signal() }
}

@MainActor final class ProgressiveSyncTests: XCTestCase {
    private var directory: URL!
    private var core: ProgressiveCore!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let real = try createCore(dbPath: directory.appendingPathComponent("local.sqlite").path,
            keystore: MemoryKeystore(), secretStore: MemorySecretStore())
        _ = try real.seedOfflineFixture(password: UUID().uuidString)
        for title in ["First", "Second"] {
            _ = try real.itemCreate(create: .init(title: title, path: title, typeId: "note",
                payloadJson: #"{"v":1,"typeId":"note","fields":{"text":{"kind":"text","value":"fixture"}}}"#))
        }
        core = ProgressiveCore(unsafeFromRawPointer: real.uniffiClonePointer())
    }
    override func tearDownWithError() throws {
        core?.release(); core = nil
        try? FileManager.default.removeItem(at: directory)
    }
    private func until(_ predicate: () -> Bool) async throws {
        for _ in 0..<300 {
            if predicate() { return }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("progress did not reach the UI before the remaining sync was released")
    }

    func testCatalogAndPagesAppearBeforeSyncFinishesAndSearchStaysUsable() async throws {
        let model = VaultModel(core: core, contents: try VaultModel.load(core), strings: Strings(language: "en"))
        XCTAssertTrue(model.awaitingFirstSync)
        let sync = Task { await model.sync() }
        try await until { model.storageID != nil }
        XCTAssertFalse(model.storages.isEmpty)
        XCTAssertFalse(model.vaults.isEmpty)
        XCTAssertTrue(model.visibleItems.isEmpty)
        XCTAssertTrue(model.syncing)
        core.catalogGate.signal()
        try await until { model.visibleItems.count == 1 }
        model.select(model.visibleItems[0].id)
        try await until { model.detail != nil }
        let selected = model.selectedItemID
        model.query = "First"
        try await until { !model.searching }
        XCTAssertEqual(model.visibleItems.map(\.title), ["First"])
        core.pageGate.signal()
        model.query = ""
        try await until { model.visibleItems.count == 2 }
        XCTAssertEqual(model.selectedItemID, selected)
        XCTAssertTrue(model.syncing)
        core.finishGate.signal()
        await sync.value
        XCTAssertFalse(model.awaitingFirstSync)
        XCTAssertFalse(model.syncing)
        XCTAssertNil(model.syncError)
    }

    func testLaterFailureKeepsCommittedItemsAndReportsBootstrapError() async throws {
        core.failAfterPage = true
        let model = VaultModel(core: core, contents: try VaultModel.load(core), strings: Strings(language: "en"))
        let sync = Task { await model.sync() }
        try await until { model.storageID != nil }
        core.catalogGate.signal()
        try await until { model.visibleItems.count == 1 }
        core.pageGate.signal()
        await sync.value
        XCTAssertEqual(model.visibleItems.map(\.title), ["First"])
        XCTAssertTrue(try XCTUnwrap(model.syncError).contains("later page failed"))
        XCTAssertFalse(model.syncing)
    }

    func testSearchRevisionCannotDiscardTheFirstCatalog() async throws {
        let model = VaultModel(core: core, contents: try VaultModel.load(core), strings: Strings(language: "en"))
        let read = expectation(description: "catalog read held")
        let gate = DispatchSemaphore(value: 0)
        core.catalogReadGate = gate
        core.onCatalogRead = { read.fulfill() }
        defer { gate.signal(); core.release() }
        let sync = Task { await model.sync() }
        await fulfillment(of: [read], timeout: 3)
        model.query = "First"
        try await until { !model.searching }
        gate.signal()
        try await until { model.storageID != nil }
        XCTAssertFalse(model.vaults.isEmpty)
        XCTAssertEqual(model.query, "First")
        core.release()
        await sync.value
        XCTAssertFalse(model.awaitingFirstSync)
        XCTAssertNotNil(model.storageID)
        XCTAssertNil(model.syncError)
    }

    func testFirstCacheReadinessSurvivesReopenAndDoesNotFollowAnotherServer() async throws {
        let other = try seedStorageContext(database: directory.appendingPathComponent("local.sqlite"),
            sourceStorageID: try XCTUnwrap(core.fixtureStorageID))
        let model = VaultModel(core: core, contents: try VaultModel.load(core), strings: Strings(language: "en"))
        let sync = Task { await model.sync() }
        defer { core.release() }
        try await until { model.storageID != nil }
        XCTAssertTrue(model.awaitingFirstSync)
        let reopened = VaultModel(core: core, contents: try VaultModel.load(core), strings: Strings(language: "en"))
        XCTAssertTrue(reopened.awaitingFirstSync, "catalog alone is not a completed cache")
        await model.selectStorage(other)
        XCTAssertEqual(model.storageID, other)
        XCTAssertFalse(model.syncing)
        XCTAssertFalse(model.awaitingFirstSync, "the original server's loader must not follow navigation")
        core.release()
        await sync.value
        XCTAssertEqual(model.storageID, other)
        XCTAssertNil(model.syncError)
    }

    func testBurstCoalescesToLatestNoticeAndCancellationIgnoresLateCallbacks() async {
        var received: [UInt64] = []
        let relay = SyncCommitRelay { received.append($0.pagesCommitted) }
        for count in 1...10_000 {
            relay.committed(update: .init(storageId: "fixture", phase: .page,
                pagesCommitted: UInt64(count), changesCommitted: UInt64(count)))
        }
        await relay.finish()
        XCTAssertEqual(received, [10_000])
        relay.cancel()
        relay.committed(update: .init(storageId: "fixture", phase: .page, pagesCommitted: 10_001, changesCommitted: 10_001))
        await relay.finish()
        XCTAssertEqual(received, [10_000])
    }
}
