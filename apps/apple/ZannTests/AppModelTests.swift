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

    private func makeModel() -> AppModel {
        let database = directory.appendingPathComponent("local.sqlite").path
        return AppModel(opening: {
            try createCore(dbPath: database, keystore: MemoryKeystore(), secretStore: MemorySecretStore())
        }, language: "en")
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

    func testUnopenableDatabaseShowsFailure() {
        let model = AppModel(opening: {
            try createCore(dbPath: "relative/local.sqlite", keystore: MemoryKeystore(), secretStore: MemorySecretStore())
        }, language: "en")
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
