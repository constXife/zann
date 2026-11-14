import XCTest
import ZannCoreKit
@testable import Zann

/// Drives AppModel against the real Rust core over a temporary database and
/// in-memory platform ports, so no Keychain item or user data is touched.
private final class EnrollmentRequiredCore: CoreFacade {
    override func activateConnectedAccount() throws -> Bool { false }
}

@MainActor
final class AppModelTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("zann-app-model-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    /// `name` picks the database and preferences file, so one test can
    /// compare several apps.
    private func makeModel(
        _ name: String = "local", keystore: MemoryKeystore = MemoryKeystore(), seed: Bool = true
    ) -> AppModel {
        let database = directory.appendingPathComponent(name, isDirectory: true)
            .appendingPathComponent("local.sqlite").path
        let preferences = directory.appendingPathComponent("\(name).preferences.json")
        return AppModel(opening: {
            let core = try createCore(
                dbPath: database, keystore: keystore, secretStore: MemorySecretStore()
            )
            if seed, try core.listStorages().isEmpty {
                _ = try core.seedOfflineFixture(password: "correct horse battery")
                _ = try core.lock()
            }
            return (core, keystore)
        }, preferences: { PreferencesFile(url: preferences) }, systemLanguage: "en",
        openBrowser: { _ in })
    }

    private func unlockedModel(
        _ change: (inout DevicePreferencesFfi) -> Void
    ) async -> AppModel {
        let model = makeModel(UUID().uuidString)
        model.updatePreferences(change)
        XCTAssertNil(model.settingsError)
        await model.submit(password: "correct horse battery", mode: .unlock)
        XCTAssertEqual(model.screen, .vault)
        return model
    }

    func testFirstLaunchConnectsAndACachedReplicaLocksAndUnlocks() async {
        let fresh = makeModel("fresh", seed: false)
        XCTAssertEqual(fresh.screen, .welcome)
        fresh.startConnecting()
        XCTAssertEqual(fresh.screen, .connect)
        let model = makeModel()
        XCTAssertEqual(model.screen, .master(.unlock))

        await model.submit(password: "correct horse battery", mode: .unlock)
        XCTAssertNil(model.error)
        XCTAssertEqual(model.screen, .vault)
        XCTAssertEqual(model.vault?.visibleItems.isEmpty, true)

        await model.lock()
        XCTAssertEqual(model.screen, .master(.unlock))
        XCTAssertNil(model.vault)

        await model.submit(password: "wrong password", mode: .unlock)
        XCTAssertNotNil(model.error)
        XCTAssertEqual(model.screen, .master(.unlock))

        await model.submit(password: "correct horse battery", mode: .unlock)
        XCTAssertNil(model.error)
        XCTAssertEqual(model.screen, .vault)
    }

    func testInitializedVaultOpensOnUnlock() async {
        let first = makeModel()
        await first.submit(password: "correct horse battery", mode: .unlock)
        XCTAssertEqual(first.screen, .vault)

        XCTAssertEqual(makeModel().screen, .master(.unlock))
    }

    func testIdleLockCountsFromTheLastActivity() async {
        let model = await unlockedModel { $0.autoLockMinutes = 1 }
        let start = Date()
        model.noteActivity(at: start)

        await model.checkIdle(at: start.addingTimeInterval(59))
        XCTAssertEqual(model.screen, .vault)

        model.noteActivity(at: start.addingTimeInterval(30))
        await model.checkIdle(at: start.addingTimeInterval(60))
        XCTAssertEqual(model.screen, .vault)

        await model.checkIdle(at: start.addingTimeInterval(90))
        XCTAssertEqual(model.screen, .master(.unlock))
        XCTAssertNil(model.vault)
    }

    func testZeroMinutesNeverIdlesOut() async {
        let model = await unlockedModel { $0.autoLockMinutes = 0 }
        await model.checkIdle(at: Date().addingTimeInterval(86_400))
        XCTAssertEqual(model.screen, .vault)
    }

    func testFocusLossAndHidingLockOnlyWhenEnabled() async {
        let kept = await unlockedModel { $0.lockOnFocusLoss = false; $0.lockOnHidden = false }
        await kept.appResignedActive()
        await kept.appHidden()
        XCTAssertEqual(kept.screen, .vault)

        let focus = await unlockedModel { $0.lockOnFocusLoss = true }
        await focus.appResignedActive()
        XCTAssertEqual(focus.screen, .master(.unlock))

        let hidden = await unlockedModel { $0.lockOnHidden = true }
        await hidden.appHidden()
        XCTAssertEqual(hidden.screen, .master(.unlock))
    }

    func testTranslationsFillInTheirPlaceholders() {
        let strings = Strings(language: "en")
        let text = strings("settings.accounts.forgetServerConfirm", ["server": "Work"])
        XCTAssertTrue(text.hasPrefix("Forget Work?"), text)
        XCTAssertFalse(text.contains("{server}"))
    }

    func testSettingsPersistAndSwitchTheLanguage() throws {
        let model = makeModel()
        XCTAssertEqual(model.preferences, devicePreferencesDefault())
        XCTAssertEqual(model.strings("nav.allItems"), "All items")

        model.updatePreferences {
            $0.autoLockMinutes = 30
            $0.language = "ru"
        }
        XCTAssertNil(model.settingsError)
        XCTAssertEqual(model.strings("nav.allItems"), "Все записи")

        let reopened = makeModel()
        XCTAssertEqual(reopened.preferences.autoLockMinutes, 30)
        XCTAssertEqual(reopened.strings("nav.allItems"), "Все записи")
        let file = directory.appendingPathComponent("local.preferences.json").path
        let mode = try FileManager.default.attributesOfItem(atPath: file)[.posixPermissions] as? Int
        XCTAssertEqual(mode, 0o600)
    }

    func testUnreadablePreferencesShowFailureInsteadOfDefaults() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data(#"{"auto_lock_minutes":"soon"}"#.utf8)
            .write(to: directory.appendingPathComponent("local.preferences.json"))
        guard case .failed(let message) = makeModel().screen else {
            return XCTFail("expected the failure screen")
        }
        XCTAssertTrue(message.contains("device preferences"), message)
    }

    func testFirstAccountUsesADevicePasswordBeforeItsEncryptionPassword() async throws {
        for existing in [false, true] {
            let root = directory.appendingPathComponent(UUID().uuidString)
            let real = try createCore(dbPath: root.appendingPathComponent("local.sqlite").path,
                keystore: MemoryKeystore(), secretStore: MemorySecretStore())
            let core = EnrollmentRequiredCore(unsafeFromRawPointer: real.uniffiClonePointer())
            let model = AppModel(opening: { (core, MemoryKeystore()) },
                preferences: { PreferencesFile(url: root.appendingPathComponent("preferences.json")) },
                systemLanguage: "en", openBrowser: { _ in })
            model.startConnecting()
            model.connected(.init(hasPersonalKeys: existing))
            XCTAssertEqual(model.screen, .master(.create))
            await model.submit(password: "one device unlock password", mode: .create)
            XCTAssertNil(model.error)
            XCTAssertFalse(model.busy)
            XCTAssertNil(model.vault)
            XCTAssertEqual(model.screen, .master(existing ? .accountUnlock : .accountCreate))
        }
    }

    func testTouchIDArmsUnlocksAndDisarms() async {
        let keystore = MemoryKeystore()
        let model = makeModel(keystore: keystore)
        await model.submit(password: "correct horse battery", mode: .unlock)
        XCTAssertFalse(model.touchIDArmed)
        XCTAssertEqual(keystore.promptReason, "unlock your vault")

        await model.setTouchID(true)
        XCTAssertNil(model.settingsError)
        XCTAssertTrue(model.touchIDArmed)
        XCTAssertTrue(makeModel().touchIDArmed, "armed state survives a relaunch")

        await model.lock()
        await model.unlockWithTouchID()
        XCTAssertEqual(model.screen, .vault)

        await model.setTouchID(false)
        XCTAssertFalse(model.touchIDArmed)
        XCTAssertFalse(keystore.holdsKey)
    }

    func testPasswordChangeKeepsTouchIDAndRejectsThePreviousPassword() async throws {
        let model = makeModel(keystore: MemoryKeystore())
        await model.submit(password: "correct horse battery", mode: .unlock)
        await model.setTouchID(true)
        let core = try XCTUnwrap(model.browserCore)
        try await Task.detached {
            try core.changeUnlockPassword(current: "correct horse battery", replacement: "new device password")
        }.value
        await model.lock()
        await model.unlockWithTouchID()
        XCTAssertEqual(model.screen, .vault)
        await model.lock()
        await model.submit(password: "correct horse battery", mode: .unlock)
        XCTAssertEqual(model.screen, .master(.unlock))
        XCTAssertNotNil(model.error)
        await model.submit(password: "new device password", mode: .unlock)
        XCTAssertEqual(model.screen, .vault)
        XCTAssertNil(model.error)
    }

    func testTouchIDChangesRunOneAtATimeAndDisarmWithoutBiometrics() async {
        let keystore = MemoryKeystore()
        let model = makeModel(keystore: keystore)
        await model.submit(password: "correct horse battery", mode: .unlock)

        // A second change while one runs is refused, never interleaved.
        async let first: Void = model.setTouchID(true)
        async let second: Void = model.setTouchID(false)
        _ = await (first, second)
        XCTAssertEqual(model.touchIDArmed, keystore.holdsKey)
        XCTAssertFalse(model.touchIDBusy)

        await model.setTouchID(true)
        keystore.biometricsAvailable = false
        await model.lock()
        await model.setTouchID(false)
        XCTAssertFalse(model.touchIDArmed)
        XCTAssertFalse(keystore.holdsKey)
    }

    func testUnreadableRememberedUnlockKeepsThePasswordWorking() async throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let first = makeModel()
        await first.submit(password: "correct horse battery", mode: .unlock)
        try Data("not json".utf8).write(to: directory.appendingPathComponent("local/unlock.json"))

        let model = makeModel()
        XCTAssertEqual(model.screen, .master(.unlock))
        XCTAssertFalse(model.touchIDArmed)
        XCTAssertNotNil(model.error)
        await model.submit(password: "correct horse battery", mode: .unlock)
        XCTAssertEqual(model.screen, .vault)
    }

    func testDismissedTouchIDPromptLeavesNoError() async {
        let keystore = MemoryKeystore()
        let model = makeModel(keystore: keystore)
        await model.submit(password: "correct horse battery", mode: .unlock)
        await model.setTouchID(true)
        await model.lock()

        keystore.cancelLoads = true
        await model.unlockWithTouchID()
        XCTAssertEqual(model.screen, .master(.unlock))
        XCTAssertNil(model.error)
    }

    func testStartupTouchIDUnlocksOnceAndManualLockKeepsTheButtonAvailable() async {
        let keystore = MemoryKeystore()
        let first = makeModel(keystore: keystore)
        await first.submit(password: "correct horse battery", mode: .unlock)
        await first.setTouchID(true)
        let model = makeModel(keystore: keystore)
        let loads = keystore.loadCalls

        async let startup: Void = model.unlockWithTouchIDAtStartup()
        async let reactivation: Void = model.unlockWithTouchIDAtStartup()
        _ = await (startup, reactivation)
        XCTAssertEqual(model.screen, .vault)
        XCTAssertEqual(keystore.loadCalls, loads + 1)

        await model.lock()
        await model.unlockWithTouchIDAtStartup()
        XCTAssertEqual(model.screen, .master(.unlock))
        XCTAssertEqual(keystore.loadCalls, loads + 1)

        await model.unlockWithTouchID()
        XCTAssertEqual(model.screen, .vault)
        XCTAssertEqual(keystore.loadCalls, loads + 2)
    }

    func testCancelledStartupTouchIDDoesNotPromptAgainAndPasswordStillWorks() async {
        let keystore = MemoryKeystore()
        let first = makeModel(keystore: keystore)
        await first.submit(password: "correct horse battery", mode: .unlock)
        await first.setTouchID(true)
        keystore.cancelLoads = true
        let model = makeModel(keystore: keystore)
        let loads = keystore.loadCalls

        await model.unlockWithTouchIDAtStartup()
        await model.unlockWithTouchIDAtStartup()
        XCTAssertEqual(keystore.loadCalls, loads + 1)
        XCTAssertEqual(model.screen, .master(.unlock))
        XCTAssertNil(model.error)
        XCTAssertFalse(model.busy)

        await model.submit(password: "correct horse battery", mode: .unlock)
        XCTAssertEqual(model.screen, .vault)
    }

    func testUnavailableStartupTouchIDDoesNotRetryOnReactivation() async {
        let keystore = MemoryKeystore()
        let first = makeModel(keystore: keystore)
        await first.submit(password: "correct horse battery", mode: .unlock)
        await first.setTouchID(true)
        let model = makeModel(keystore: keystore)
        let loads = keystore.loadCalls
        keystore.biometricsAvailable = false

        await model.unlockWithTouchIDAtStartup()
        keystore.biometricsAvailable = true
        await model.unlockWithTouchIDAtStartup()
        XCTAssertEqual(keystore.loadCalls, loads)
        XCTAssertEqual(model.screen, .master(.unlock))
        XCTAssertNil(model.error)

        await model.unlockWithTouchID()
        XCTAssertEqual(model.screen, .vault)
    }

    func testPasswordAttemptPreventsADelayedStartupTouchIDPrompt() async {
        let keystore = MemoryKeystore()
        let first = makeModel(keystore: keystore)
        await first.submit(password: "correct horse battery", mode: .unlock)
        await first.setTouchID(true)
        let model = makeModel(keystore: keystore)
        let loads = keystore.loadCalls

        await model.submit(password: "wrong password", mode: .unlock)
        await model.unlockWithTouchIDAtStartup()
        XCTAssertEqual(keystore.loadCalls, loads)
        XCTAssertEqual(model.screen, .master(.unlock))
        XCTAssertNotNil(model.error)
    }

    func testUnopenableDatabaseShowsFailure() {
        let preferences = directory.appendingPathComponent("preferences.json")
        let model = AppModel(opening: {
            let keystore = MemoryKeystore()
            let core = try createCore(
                dbPath: "relative/local.sqlite", keystore: keystore, secretStore: MemorySecretStore()
            )
            return (core, keystore)
        }, preferences: { PreferencesFile(url: preferences) }, systemLanguage: "en",
        openBrowser: { _ in })
        guard case .failed = model.screen else {
            return XCTFail("expected the failure screen, got \(model.screen)")
        }
    }
}

/// A keystore that always "passes" Touch ID, unless `cancelLoads` makes it
/// behave like a dismissed prompt.
final class MemoryKeystore: DeviceKeystore {
    private var dwk: Data?
    private(set) var promptReason = ""
    var cancelLoads = false
    var biometricsAvailable = true
    private(set) var loadCalls = 0

    var holdsKey: Bool { dwk != nil }

    func setPromptReason(_ reason: String) { promptReason = reason }

    func status() -> PlatformKeystoreStatus {
        PlatformKeystoreStatus(
            supported: true, biometricsAvailable: biometricsAvailable, reason: nil, message: nil
        )
    }

    func storeDwk(dwk: Data) throws { self.dwk = dwk }

    func loadDwk() throws -> Data? {
        loadCalls += 1
        if cancelLoads { throw PlatformStoreError.Cancelled }
        return dwk
    }

    func deleteDwk() throws { dwk = nil }
}

final class MemorySecretStore: PlatformSecretStore {
    private var values: [String: String] = [:]

    func put(service: String, account: String, secret: String) throws {
        values["\(service)/\(account)"] = secret
    }

    func get(service: String, account: String) throws -> String? {
        values["\(service)/\(account)"]
    }

    func delete(service: String, account: String) throws {
        values["\(service)/\(account)"] = nil
    }
}
