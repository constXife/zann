import XCTest
import ZannCoreKit
#if os(iOS)
@testable import ZannMobile
#else
@testable import Zann
#endif

@MainActor final class OfflineLifecycleTests: XCTestCase {
    func testOfflineCreateEditSearchAndPendingSurviveReopenWithoutDuplicates() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let database = directory.appendingPathComponent("local.sqlite")
        let keystore = MemoryKeystore()
        let secrets = MemorySecretStore()
        let password = "offline lifecycle fixture"
        let storage: String
        let id: String
        let pending: UInt64
        do {
            let core = try createCore(dbPath: database.path, keystore: keystore, secretStore: secrets)
            _ = try core.seedOfflineFixture(password: password)
            storage = try XCTUnwrap(core.currentStorageId())
            let vault = VaultModel(core: core, contents: try VaultModel.load(core), strings: Strings(language: "en"))
            vault.startCreating(typeID: "note")
            try XCTUnwrap(vault.editor).name = "Offline original"
            await vault.saveEditor()
            id = try XCTUnwrap(vault.visibleItems.first?.id)
            vault.select(id)
            for _ in 0..<200 where vault.detailLoading { try await Task.sleep(nanoseconds: 10_000_000) }
            XCTAssertTrue(vault.canEdit)
            await vault.startEditing()
            try XCTUnwrap(vault.editor).name = "Offline edited"
            await vault.saveEditor()
            XCTAssertNil(vault.editor)
            pending = try core.storageSyncState(storageId: storage).pendingChanges
            XCTAssertGreaterThan(pending, 0)
            _ = try core.lock()
        }
        let reopened = try createCore(dbPath: database.path, keystore: keystore, secretStore: secrets)
        XCTAssertTrue(try reopened.appStatus().locked)
        _ = try reopened.unlock(password: password)
        let vault = VaultModel(core: reopened, contents: try VaultModel.load(reopened), strings: Strings(language: "en"))
        XCTAssertEqual(vault.visibleItems.map(\.id), [id])
        XCTAssertEqual(vault.visibleItems.map(\.title), ["Offline edited"])
        vault.query = "edited"
        for _ in 0..<200 where vault.searching { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertFalse(vault.searching)
        XCTAssertEqual(vault.visibleItems.map(\.id), [id])
        XCTAssertEqual(try reopened.storageSyncState(storageId: storage).pendingChanges, pending)
        XCTAssertEqual(try reopened.verify().itemsOk, 1)
    }

    func testForegroundResumesRetainedUnlockedSchedulerAndSyncsSavedChanges() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let real = try createCore(dbPath: directory.appendingPathComponent("local.sqlite").path,
                                  keystore: MemoryKeystore(), secretStore: MemorySecretStore())
        _ = try real.seedOfflineFixture(password: "foreground fixture password")
        _ = try real.lock()
        let core = UXDelayedCore(wrapping: real)
        let first = expectation(description: "initial sync")
        core.onSync = { first.fulfill() }
        let app = AppModel(opening: { (core, MemoryKeystore()) }, preferences: {
            PreferencesFile(url: directory.appendingPathComponent("preferences.json"))
        }, systemLanguage: "en", browser: .loopback(open: { _ in }))
        app.updatePreferences { $0.lockOnHidden = false; $0.lockOnFocusLoss = false; $0.autoLockMinutes = 0 }
        await app.submit(password: "foreground fixture password", mode: .unlock)
        let vault = try XCTUnwrap(app.vault)
        await fulfillment(of: [first], timeout: 3)
        // Let the already-admitted sync settle without requesting another.
        for _ in 0..<200 where vault.syncing { try await Task.sleep(nanoseconds: 10_000_000) }
        await app.secureForBackground().value
        XCTAssertTrue(app.vault === vault)
        XCTAssertTrue(app.isUnlocked)
        let foreground = expectation(description: "foreground sync is admitted")
        core.onSync = { foreground.fulfill() }
        await app.resumeFromBackground()
        await fulfillment(of: [foreground], timeout: 3)
        for _ in 0..<200 where vault.syncing { try await Task.sleep(nanoseconds: 10_000_000) }
        let edited = expectation(description: "post-edit scheduled sync")
        core.onSync = { edited.fulfill() }
        vault.startCreating(typeID: "note")
        try XCTUnwrap(vault.editor).name = "Saved after foreground"
        await vault.saveEditor()
        await fulfillment(of: [edited], timeout: 5)
        await app.lock()
    }
}
