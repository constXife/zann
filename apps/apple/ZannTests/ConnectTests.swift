import XCTest
import ZannCoreKit
@testable import Zann

/// The connect flow over the real core. The live test needs a server with
/// open registration and password sign-in:
/// `TEST_RUNNER_ZANN_REMOTE_URL=http://127.0.0.1:18081 xcodebuild test ...`.
@MainActor
final class ConnectTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("zann-connect-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    /// One device: its own directory, which holds the database, the client
    /// config beside it and the preferences, plus in-memory ports.
    private func makeDevice(_ name: String) -> AppModel {
        let root = directory.appendingPathComponent(name, isDirectory: true)
        let database = root.appendingPathComponent("local.sqlite").path
        let preferences = root.appendingPathComponent("preferences.json")
        return AppModel(opening: {
            let keystore = MemoryKeystore()
            let core = try createCore(
                dbPath: database, keystore: keystore, secretStore: MemorySecretStore()
            )
            return (core, keystore)
        }, preferences: { PreferencesFile(url: preferences) }, systemLanguage: "en",
        openBrowser: { _ in })
    }

    func testAnUnreachableServerStaysOnTheServerStep() async throws {
        let closed = try closedPort()
        let model = makeDevice("offline")
        model.startConnecting()
        let connect = try XCTUnwrap(model.connect)
        XCTAssertEqual(model.screen, .connect)

        connect.url = "http://127.0.0.1:\(closed)"
        await connect.probe()
        XCTAssertEqual(connect.stage, .server)
        XCTAssertNotNil(connect.error)

        XCTAssertFalse(connect.back())
        model.leaveConnecting()
        XCTAssertEqual(model.screen, .welcome)
        XCTAssertNil(model.connect)
    }

    /// Going back while a call runs discards what it returns, even success.
    func testAProbeTheUserLeftBehindChangesNothing() async throws {
        guard let url = ProcessInfo.processInfo.environment["ZANN_REMOTE_URL"], !url.isEmpty
        else { throw XCTSkip("ZANN_REMOTE_URL is not set") }
        let model = makeDevice("left")
        model.startConnecting()
        let connect = try XCTUnwrap(model.connect)
        connect.url = url
        let probe = Task { await connect.probe() }
        while !connect.busy { await Task.yield() }
        connect.cancel()
        XCTAssertFalse(connect.busy)
        await probe.value
        XCTAssertEqual(connect.stage, .server)
        XCTAssertTrue(connect.methods.isEmpty)
        XCTAssertNil(connect.error)
    }

    /// A new account: device A signs in, creates the personal vault and
    /// publishes an item; device B signs in to the same account, opens its
    /// vault with the same master password and sees the item after the first
    /// sync.
    func testASecondMacOpensTheVaultTheFirstPublished() async throws {
        guard let url = ProcessInfo.processInfo.environment["ZANN_REMOTE_URL"], !url.isEmpty
        else { throw XCTSkip("ZANN_REMOTE_URL is not set") }
        let suffix = UUID().uuidString.lowercased()
        let email = "apple-\(suffix)@example.test"
        let account = "account-password-\(suffix)"
        let master = "master-password-\(suffix)"

        try registerAccount(url: url, email: email, password: account)

        let deviceA = makeDevice("a")
        try await signIn(deviceA, url: url, email: email, password: account)
        XCTAssertEqual(deviceA.screen, .master(.create))
        XCTAssertTrue(deviceA.syncAfterUnlock)
        await deviceA.submit(password: master, mode: .create)
        XCTAssertNil(deviceA.error)
        let vaultA = try XCTUnwrap(deviceA.vault)
        XCTAssertTrue(vaultA.canSync)
        XCTAssertNil(vaultA.syncError)

        vaultA.startCreating(typeID: "note")
        let editor = try XCTUnwrap(vaultA.editor)
        editor.setPath("Shared/From A")
        await vaultA.saveEditor()
        XCTAssertNil(vaultA.editor)
        await vaultA.sync()
        XCTAssertNil(vaultA.syncError)

        let deviceB = makeDevice("b")
        try await signIn(deviceB, url: url, email: email, password: account)
        XCTAssertEqual(deviceB.screen, .master(.unlock))
        // A typo is refused against the account's key and binds nothing.
        await deviceB.submit(password: master + "x", mode: .unlock)
        XCTAssertNotNil(deviceB.error)
        XCTAssertEqual(deviceB.screen, .master(.unlock))
        await deviceB.submit(password: master, mode: .unlock)
        XCTAssertNil(deviceB.error)
        let vaultB = try XCTUnwrap(deviceB.vault)
        XCTAssertNil(vaultB.syncError)
        XCTAssertEqual(vaultB.visibleItems.map(\.path), ["Shared/From A"])

        // A later unlock opens at once and still knows its server.
        await deviceB.lock()
        await deviceB.submit(password: master, mode: .unlock)
        let reopened = try XCTUnwrap(deviceB.vault)
        await reopened.sync()
        XCTAssertTrue(reopened.canSync)
        XCTAssertNil(reopened.syncError)
        XCTAssertEqual(reopened.visibleItems.map(\.path), ["Shared/From A"])
    }

    /// The core offers registration only on a server without users, so the
    /// account comes from a throwaway core rather than through either device.
    private func registerAccount(url: String, email: String, password: String) throws {
        let core = try createCore(
            dbPath: directory.appendingPathComponent("registrar/local.sqlite").path,
            keystore: MemoryKeystore(), secretStore: MemorySecretStore()
        )
        let session = try core.remoteSession()
        guard case .ready(let connection) = try session.prepareConnection(
            endpoint: url, connectionName: "Remote", profileName: "default"
        ) else { return XCTFail("a fresh database has no pinned fingerprint") }
        _ = try session.passwordRegister(
            connection: connection, email: email, password: password, fullName: nil,
            operation: try SessionOperationFfi(timeoutMs: 60_000)
        )
    }

    private func signIn(
        _ model: AppModel, url: String, email: String, password: String
    ) async throws {
        model.startConnecting()
        let connect = try XCTUnwrap(model.connect)
        connect.url = url
        await connect.probe()
        XCTAssertNil(connect.error)
        if connect.stage == .methods { connect.choosePassword() }
        XCTAssertEqual(connect.stage, .password(register: false))
        connect.email = email
        await connect.submitPassword(password)
        XCTAssertNil(connect.error)
        XCTAssertNil(model.connect)
    }

    private func closedPort() throws -> UInt16 {
        let socket = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        defer { close(socket) }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        try withUnsafeMutablePointer(to: &address) { pointer in
            try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                guard Darwin.bind(socket, $0, length) == 0, getsockname(socket, $0, &length) == 0 else {
                    throw POSIXError(.EADDRINUSE)
                }
            }
        }
        return UInt16(bigEndian: address.sin_port)
    }
}
