import XCTest
import Security
import ZannCoreKit
#if os(iOS)
@testable import ZannMobile
#else
@testable import Zann
#endif

@MainActor
final class MobileSecurityTests: XCTestCase {
    func testClipboardExpiryAndStaleTimersNeverEraseAnotherWrite() async throws {
        let sink = MemoryClipboard()
        let clipboard = ClipboardController(sink: sink)
        clipboard.copy("first", clearAfter: 1, onlyIfUnchanged: true)
        clipboard.copy("second", clearAfter: 60, onlyIfUnchanged: true)
        try await Task.sleep(nanoseconds: 1_050_000_000)
        XCTAssertEqual(sink.value, "second")
        sink.write("another app", expiration: nil)
        clipboard.reconcile(now: Date().addingTimeInterval(61))
        XCTAssertEqual(sink.value, "another app")
        clipboard.copy("owned", clearAfter: 60, onlyIfUnchanged: false)
        sink.write("new user clipboard", expiration: nil)
        clipboard.clearOwned()
        XCTAssertEqual(sink.value, "new user clipboard")
        clipboard.copy("expire", clearAfter: 60, onlyIfUnchanged: true)
        XCTAssertNotNil(sink.expiration)
        clipboard.reconcile(now: Date().addingTimeInterval(61))
        XCTAssertNil(sink.value)
    }

    func testScopedKeychainQueriesNeverAddressAnotherAccessGroup() throws {
        for group in ["TEAM.app-private", "TEAM.vault-shared"] {
            for protected in [false, true] {
                let query = Keychain.itemQuery(service: "test-service", account: "test-account", dataProtection: protected, scope: .accessGroup(group))
                XCTAssertEqual(query[kSecAttrAccessGroup] as? String, group)
                XCTAssertEqual(query[kSecUseDataProtectionKeychain] as? Bool, true)
                XCTAssertEqual(query[kSecAttrService] as? String, "test-service")
            }
        }
        XCTAssertThrowsError(try Keychain.check(errSecMissingEntitlement)) {
            guard case PlatformStoreError.Unsupported = $0 else { return XCTFail("entitlement error must fail closed") }
        }
        XCTAssertThrowsError(try Keychain.check(errSecInteractionNotAllowed)) {
            guard case PlatformStoreError.Unavailable(let message) = $0 else { return XCTFail("protected data must remain unavailable") }
            XCTAssertTrue(message.contains(String(errSecInteractionNotAllowed)))
        }
    }

    func testBackgroundDropsLateBiometricSuccessAndClosesTheCore() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let keystore = MemoryKeystore()
        let core = try createCore(dbPath: directory.appendingPathComponent("local.sqlite").path, keystore: keystore, secretStore: MemorySecretStore())
        _ = try core.seedOfflineFixture(password: "background test password")
        _ = try core.lock()
        let model = AppModel(opening: { (core, keystore) }, preferences: {
            PreferencesFile(url: directory.appendingPathComponent("preferences.json"))
        }, systemLanguage: "en", browser: .loopback(open: { _ in }))
        await model.submit(password: "background test password", mode: .unlock)
        await model.setTouchID(true)
        await model.lock()
        model.updatePreferences { $0.lockOnHidden = false }
        let entered = expectation(description: "biometric request entered")
        let gate = DispatchSemaphore(value: 0)
        keystore.onLoad = { entered.fulfill(); gate.wait() }
        let unlocking = Task { await model.unlockWithTouchID() }
        await fulfillment(of: [entered], timeout: 3)
        let locking = model.secureForBackground()
        gate.signal()
        await unlocking.value
        await locking.value
        XCTAssertEqual(model.screen, .master(.unlock))
        XCTAssertNil(model.vault)
        XCTAssertFalse(model.busy)
        XCTAssertGreaterThan(keystore.cancelCalls, 0)
        XCTAssertTrue(try core.appStatus().locked)
    }

    func testLogoutLocksEvenBeforeTheFirstCatalogSelectsAStorage() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let keystore = MemoryKeystore()
        let base = try createCore(dbPath: directory.appendingPathComponent("local.sqlite").path, keystore: keystore, secretStore: MemorySecretStore())
        _ = try base.seedOfflineFixture(password: "logout test password")
        _ = try base.lock()
        let core = CatalogPendingCore(unsafeFromRawPointer: base.uniffiClonePointer())
        let model = AppModel(opening: { (core, keystore) }, preferences: {
            PreferencesFile(url: directory.appendingPathComponent("preferences.json"))
        }, systemLanguage: "en", browser: .loopback(open: { _ in }))
        await model.submit(password: "logout test password", mode: .unlock)
        XCTAssertEqual(model.screen, .vault)
        XCTAssertNil(model.vault?.storageID)
        await model.logout()
        XCTAssertEqual(model.screen, .master(.unlock))
        XCTAssertNil(model.vault)
        XCTAssertTrue(try base.appStatus().locked)
        // This fixture has no remote session: its canonical failure must be
        // reported after locking, rather than silently skipping logout.
        XCTAssertNotNil(model.error)
    }

    func testBackgroundDuringAccountEnrollmentRequiresDeviceUnlockFirst() async throws {
        for existingKeys in [false, true] {
            let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            defer { try? FileManager.default.removeItem(at: directory) }
            let keystore = MemoryKeystore()
            let real = try createCore(dbPath: directory.appendingPathComponent("local.sqlite").path,
                                      keystore: keystore, secretStore: MemorySecretStore())
            let core = EnrollmentPendingCore(unsafeFromRawPointer: real.uniffiClonePointer())
            let model = AppModel(opening: { (core, keystore) }, preferences: {
                PreferencesFile(url: directory.appendingPathComponent("preferences.json"))
            }, systemLanguage: "en", browser: .loopback(open: { _ in }))
            model.updatePreferences { $0.lockOnHidden = true }
            model.startConnecting()
            await model.connected(.init(storageID: "enrollment-fixture", hasPersonalKeys: existingKeys))
            await model.submit(password: "device unlock fixture password", mode: .create)
            let accountPhase: AppModel.MasterMode = existingKeys ? .accountUnlock : .accountCreate
            XCTAssertEqual(model.screen, .master(accountPhase))
            XCTAssertTrue(model.isUnlocked)

            await model.secureForBackground().value
            XCTAssertEqual(model.screen, .master(.unlock))
            XCTAssertFalse(model.isUnlocked)
            XCTAssertTrue(try real.appStatus().locked)

            await model.submit(password: "device unlock fixture password", mode: .unlock)
            XCTAssertEqual(model.screen, .master(accountPhase))
            XCTAssertNil(model.error)
        }
    }
}

private final class EnrollmentPendingCore: CoreFacade {
    override func activateConnectedAccount() throws -> Bool { false }
}

private final class CatalogPendingCore: CoreFacade {
    override func currentStorageId() -> String? { nil }
}

@MainActor
private final class MemoryClipboard: ClipboardSink {
    private(set) var changeCount = 0
    private(set) var value: String?
    private(set) var expiration: Date?
    func write(_ value: String, expiration: Date?) {
        self.value = value
        self.expiration = expiration
        changeCount += 1
    }
    func clear() { value = nil; expiration = nil; changeCount += 1 }
}
