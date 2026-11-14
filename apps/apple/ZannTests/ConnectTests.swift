import XCTest
import ZannCoreKit
@testable import Zann

/// The connect flow over the real core. The live test needs a server with
/// open registration and password sign-in:
/// `TEST_RUNNER_ZANN_REMOTE_URL=http://127.0.0.1:18081 xcodebuild test ...`.
@MainActor
final class ConnectTests: XCTestCase {
    private var directory: URL!
    /// Each device's core, so a test can check what the app asked of it.
    private var cores: [String: CoreFacade] = [:]

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("zann-connect-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDownWithError() throws {
        cores = [:]
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
            self.cores[name] = core
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

    /// After a server is forgotten the connect screen opens at its address,
    /// and backing out of it leads to the unlock screen, not the welcome.
    func testReconnectingStartsAtTheForgottenAddressAndBacksOutToUnlock() async throws {
        let model = makeDevice("reconnect")
        model.startConnecting(serverURL: "https://zann.example", returnTo: .master(.unlock))
        let connect = try XCTUnwrap(model.connect)
        XCTAssertEqual(connect.url, "https://zann.example")
        XCTAssertEqual(connect.stage, .server)

        XCTAssertFalse(connect.back())
        model.leaveConnecting()
        XCTAssertEqual(model.screen, .master(.unlock))
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
        await vaultA.sync()
        XCTAssertTrue(vaultA.canSync)
        XCTAssertNil(vaultA.syncError)

        vaultA.startCreating(typeID: "note")
        let editor = try XCTUnwrap(vaultA.editor)
        editor.name = "From A"
        editor.folder = "Shared"
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
        await vaultB.sync()
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

    /// Both Macs stay unlocked: an item saved on A appears on B within the
    /// core's sync interval, with no Sync now on either.
    func testAnEditOnOneMacReachesTheOtherWithoutSyncNow() async throws {
        guard let url = ProcessInfo.processInfo.environment["ZANN_REMOTE_URL"], !url.isEmpty
        else { throw XCTSkip("ZANN_REMOTE_URL is not set") }
        let suffix = UUID().uuidString.lowercased()
        let email = "apple-auto-\(suffix)@example.test"
        let account = "account-password-\(suffix)"
        let master = "master-password-\(suffix)"
        try registerAccount(url: url, email: email, password: account)

        let deviceA = makeDevice("a")
        try await signIn(deviceA, url: url, email: email, password: account)
        await deviceA.submit(password: master, mode: .create)
        let vaultA = try XCTUnwrap(deviceA.vault)
        await vaultA.sync()
        let deviceB = makeDevice("b")
        try await signIn(deviceB, url: url, email: email, password: account)
        await deviceB.submit(password: master, mode: .unlock)
        let vaultB = try XCTUnwrap(deviceB.vault)
        await vaultB.sync()
        XCTAssertTrue(vaultB.visibleItems.isEmpty)

        vaultA.startCreating(typeID: "note")
        try XCTUnwrap(vaultA.editor).name = "Automatic"
        try XCTUnwrap(vaultA.editor).folder = "Shared"
        await vaultA.saveEditor()

        // Two automatic syncs in one process may meet the core's one-sync
        // bound once; the next interval retries, so allow two.
        let deadline = Date().addingTimeInterval(150)
        while !vaultB.visibleItems.map(\.path).contains("Shared/Automatic") {
            guard Date() < deadline else {
                return XCTFail("B never saw A's item; last error: \(vaultB.syncError ?? "none")")
            }
            try await Task.sleep(nanoseconds: 500_000_000)
        }

        await deviceB.lock()
        XCTAssertNil(deviceB.vault)
    }

    /// Forgetting the server keeps the vault and its items on this Mac, and
    /// the vault then says that nothing syncs it and what waits for the
    /// server; connecting to the same server and account sends it.
    func testForgettingTheServerKeepsTheVaultUntilItConnectsAgain() async throws {
        guard let url = ProcessInfo.processInfo.environment["ZANN_REMOTE_URL"], !url.isEmpty
        else { throw XCTSkip("ZANN_REMOTE_URL is not set") }
        let suffix = UUID().uuidString.lowercased()
        let email = "apple-forget-\(suffix)@example.test"
        let account = "account-password-\(suffix)"
        try registerAccount(url: url, email: email, password: account)

        let device = makeDevice("forget")
        try await signIn(device, url: url, email: email, password: account)
        let master = "master-password-\(suffix)"
        await device.submit(password: master, mode: .create)
        let vault = try XCTUnwrap(device.vault)
        await vault.sync()
        XCTAssertTrue(vault.canSync)
        vault.startCreating(typeID: "note")
        try XCTUnwrap(vault.editor).name = "Local"
        try XCTUnwrap(vault.editor).folder = "Kept"
        await vault.saveEditor()
        await vault.sync()
        XCTAssertNil(vault.syncError)

        let core = try XCTUnwrap(cores["forget"])
        let storage = try XCTUnwrap(core.currentStorageId())
        XCTAssertEqual(try core.storageSyncState(storageId: storage).link, .connected)
        XCTAssertEqual(try core.pendingChangeCount(storageId: storage), 0)
        XCTAssertEqual(try core.forgetServer(storageId: storage), url)
        let gone = try core.storageSyncState(storageId: storage)
        guard gone.link == .disconnected, gone.pendingChanges == 0 else {
            return XCTFail("a forgotten server's vault stays a server's")
        }
        let kept = gone.serverUrl
        XCTAssertNotNil(kept)
        XCTAssertNil(try core.forgetServer(storageId: storage))

        await vault.sync()
        XCTAssertEqual(vault.disconnected, .init(serverURL: kept, pendingChanges: 0))
        XCTAssertNotNil(vault.syncError, "a vault nothing syncs says so")
        XCTAssertNil(vault.staleServer)
        XCTAssertEqual(vault.visibleItems.map(\.path), ["Kept/Local"])
        vault.startCreating(typeID: "note")
        try XCTUnwrap(vault.editor).name = "Unsent"
        try XCTUnwrap(vault.editor).folder = "Kept"
        await vault.saveEditor()
        XCTAssertEqual(try core.pendingChangeCount(storageId: storage), 1)
        await vault.sync()
        XCTAssertEqual(vault.disconnected, .init(serverURL: kept, pendingChanges: 1))
        XCTAssertEqual(vault.indicator?.state, .disconnected)
        XCTAssertEqual(vault.indicator?.action, .reconnect)

        await device.reconnectServer()
        XCTAssertNil(device.vault, "connecting again ends at the master password")
        XCTAssertEqual(device.screen, .connect)
        XCTAssertEqual(device.connect?.url, kept, "the connect screen starts at the vault's server")
        device.leaveConnecting()

        try await signIn(device, url: url, email: email, password: account)
        await device.submit(password: master, mode: .unlock)
        let reconnected = try XCTUnwrap(device.vault)
        await reconnected.sync()
        XCTAssertNil(reconnected.syncError)
        XCTAssertEqual(core.currentStorageId(), storage, "the new connection syncs the same vault")
        XCTAssertEqual(try core.pendingChangeCount(storageId: storage), 0)
        await device.lock()

        let witness = makeDevice("witness")
        try await signIn(witness, url: url, email: email, password: account)
        await witness.submit(password: master, mode: .unlock)
        let witnessed = try XCTUnwrap(witness.vault)
        await witnessed.sync()
        XCTAssertEqual(
            Set(witnessed.visibleItems.map(\.path)), ["Kept/Local", "Kept/Unsent"]
        )
    }


    /// A shared vault the account can reach opens from the picker with its
    /// shared category labels, and the personal vault comes back the same way.
    func testThePickerOpensASharedVaultAndComesBack() async throws {
        guard let url = ProcessInfo.processInfo.environment["ZANN_REMOTE_URL"], !url.isEmpty
        else { throw XCTSkip("ZANN_REMOTE_URL is not set") }
        let suffix = UUID().uuidString.lowercased()
        let email = "apple-vaults-\(suffix)@example.test"
        let account = "account-password-\(suffix)"
        try registerAccount(url: url, email: email, password: account)
        // Slugs are unique on the server, so each run names its own vault.
        let teamName = "Team \(suffix.prefix(8))"
        try await createSharedVault(url: url, email: email, password: account, name: teamName)

        let device = makeDevice("vaults")
        try await signIn(device, url: url, email: email, password: account)
        await device.submit(password: "master-password-\(suffix)", mode: .create)
        let vault = try XCTUnwrap(device.vault)
        await vault.sync()
        vault.startCreating(typeID: "note")
        try XCTUnwrap(vault.editor).name = "Note"
        try XCTUnwrap(vault.editor).folder = "Mine"
        await vault.saveEditor()
        await vault.sync()
        XCTAssertNil(vault.syncError)
        let personal = try XCTUnwrap(vault.vaultID)
        let team = try XCTUnwrap(vault.vaults.first { $0.name == teamName })
        XCTAssertEqual(team.scope, .shared)
        XCTAssertEqual(vault.vaults.count, 2)

        await vault.selectVault(team.id)
        XCTAssertNil(vault.error)
        XCTAssertEqual(vault.vaultID, team.id)
        XCTAssertTrue(vault.visibleItems.isEmpty)
        XCTAssertNotEqual(vault.categories.map(\.labelKey), categoryViews(
            counts: ItemCountsFfi(all: 0, trash: 0, byType: []), scope: .personal
        ).map(\.labelKey), "a shared vault labels its categories as shared")

        await vault.selectVault(personal)
        XCTAssertEqual(vault.visibleItems.map(\.path), ["Mine/Note"])
        await device.lock()
    }

    /// Signs the account in over HTTP and creates a server-encrypted shared
    /// vault, which no client creates yet.
    private func createSharedVault(url: String, email: String, password: String, name: String)
        async throws
    {
        func post(_ path: String, _ body: [String: Any], token: String? = nil) async throws -> Data {
            var request = URLRequest(url: URL(string: url + path)!)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "content-type")
            if let token { request.setValue("Bearer \(token)", forHTTPHeaderField: "authorization") }
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
            let (data, response) = try await URLSession.shared.data(for: request)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            guard (200..<300).contains(status) else {
                throw CoreError.Service("POST \(path) answered \(status)")
            }
            return data
        }
        let login = try await post("/v1/auth/login", ["email": email, "password": password])
        let token = try XCTUnwrap(
            (try JSONSerialization.jsonObject(with: login) as? [String: Any])?["access_token"] as? String
        )
        // Kind 2 is shared and cache policy 1 is full, as zann-core numbers them.
        _ = try await post(
            "/v1/vaults",
            [
                "slug": name.lowercased().replacingOccurrences(of: " ", with: "-"),
                "name": name, "kind": 2, "cache_policy": 1,
            ],
            token: token
        )
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
