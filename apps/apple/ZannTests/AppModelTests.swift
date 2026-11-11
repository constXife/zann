import XCTest
import ZannCoreKit
@testable import Zann

/// Drives AppModel against the real Rust core over a temporary database and
/// in-memory platform ports, so no Keychain item or user data is touched.
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

    private func makeModel(
        _ preferences: DevicePreferencesFfi = devicePreferencesDefault(),
        database name: String = "local"
    ) -> AppModel {
        let database = directory.appendingPathComponent("\(name).sqlite").path
        return AppModel(opening: {
            try createCore(dbPath: database, keystore: MemoryKeystore(), secretStore: MemorySecretStore())
        }, language: "en", preferences: preferences)
    }

    private func unlockedModel(
        _ edit: (inout DevicePreferencesFfi) -> Void
    ) async -> AppModel {
        var preferences = devicePreferencesDefault()
        edit(&preferences)
        // Each model gets its own vault, so one test can compare several.
        let model = makeModel(preferences, database: UUID().uuidString)
        model.startCreatingVault()
        await model.submit(password: "correct horse battery", mode: .create)
        XCTAssertEqual(model.screen, .vault)
        return model
    }

    func testFirstLaunchCreatesVaultThenLocksAndUnlocks() async {
        let model = makeModel()
        XCTAssertEqual(model.screen, .welcome)

        model.startCreatingVault()
        XCTAssertEqual(model.screen, .master(.create))

        await model.submit(password: "correct horse battery", mode: .create)
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
        first.startCreatingVault()
        await first.submit(password: "correct horse battery", mode: .create)
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

    func testUnopenableDatabaseShowsFailure() {
        let model = AppModel(opening: {
            try createCore(dbPath: "relative/local.sqlite", keystore: MemoryKeystore(), secretStore: MemorySecretStore())
        }, language: "en", preferences: devicePreferencesDefault())
        guard case .failed = model.screen else {
            return XCTFail("expected the failure screen, got \(model.screen)")
        }
    }
}

final class MemoryKeystore: PlatformKeystore {
    private var dwk: Data?

    func status() -> PlatformKeystoreStatus {
        PlatformKeystoreStatus(supported: true, biometricsAvailable: false, reason: nil, message: nil)
    }

    func storeDwk(dwk: Data) throws { self.dwk = dwk }
    func loadDwk() throws -> Data? { dwk }
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
