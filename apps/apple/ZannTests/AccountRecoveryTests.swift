import XCTest
import ZannCoreKit
@testable import Zann

@MainActor
final class AccountRecoveryTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func model(seed: Bool = true) throws -> AppModel {
        let keystore = MemoryKeystore()
        let core = try createCore(dbPath: directory.appendingPathComponent("local.sqlite").path,
                                  keystore: keystore, secretStore: MemorySecretStore())
        if seed {
            _ = try core.seedOfflineFixture(password: "correct horse battery")
            _ = try core.lock()
        }
        return AppModel(opening: { (core, keystore) },
                        preferences: { PreferencesFile(url: self.directory.appendingPathComponent("preferences.json")) },
                        systemLanguage: "en", browser: .loopback(open: { _ in }))
    }

    func testAccountNavigationPreservesUnlockAndIdleLockCoversAccountScreen() async throws {
        let app = try model()
        app.updatePreferences { $0.autoLockMinutes = 1 }
        await app.submit(password: "correct horse battery", mode: .unlock)
        app.showAccountRecovery()
        XCTAssertEqual(app.screen, .accounts)
        XCTAssertTrue(app.isUnlocked)
        XCTAssertNil(app.vault)
        let recovery = try XCTUnwrap(app.recovery)
        await recovery.reload()
        let account = try XCTUnwrap(recovery.accounts.first)
        await app.chooseSetupAccount(account)
        XCTAssertEqual(app.screen, .vault, "an enrolled account opens without another password")
        app.showAccountRecovery()
        let start = Date()
        app.noteActivity(at: start)
        await app.checkIdle(at: start.addingTimeInterval(60))
        XCTAssertEqual(app.screen, .master(.unlock))
        XCTAssertFalse(app.isUnlocked)
    }

    func testLockedRecoveryCancelPreservesAccountAndDeviceResetClearsLocalUnlock() async throws {
        let app = try model()
        app.showAccountRecovery()
        let recovery = try XCTUnwrap(app.recovery)
        await recovery.reload()
        await recovery.prepare(try XCTUnwrap(recovery.accounts.first))
        XCTAssertNotNil(recovery.preview)
        await recovery.cancel()
        XCTAssertNil(recovery.preview)
        XCTAssertEqual(recovery.accounts.count, 1)
        await recovery.prepare(nil)
        await recovery.confirm(discardUnsent: true)
        XCTAssertNil(recovery.error)
        XCTAssertNotNil(recovery.snapshotPath)
        XCTAssertTrue(recovery.accounts.isEmpty)
        XCTAssertFalse(app.isUnlocked)
        app.startConnecting(returnTo: .accounts)
        app.leaveConnecting()
        XCTAssertEqual(app.screen, .accounts)
        XCTAssertFalse(try XCTUnwrap(app.browserCore).appStatus().initialized)
    }

    func testRestartWithoutEnrollmentDoesNotGuessAccountPasswordCreation() async throws {
        let first = try model(seed: false)
        let core = try XCTUnwrap(first.browserCore)
        _ = try core.initializeMasterPassword(password: "correct horse battery")
        _ = try core.lock()
        let restarted = try model(seed: false)
        await restarted.submit(password: "correct horse battery", mode: .unlock)
        XCTAssertNil(restarted.error)
        XCTAssertEqual(restarted.screen, .accounts)
        XCTAssertTrue(restarted.isUnlocked)
    }
}
