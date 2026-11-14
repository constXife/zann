import XCTest
import ZannCoreKit
@testable import Zann

private final class ConnectPreparedFixture: PreparedConnectionFfi {
    override func authMethods() -> [AuthMethodFfi] { [.password] }
    override func registrationAvailable() -> Bool { true }
    override func serverName() -> String? { "Fixture" }
    override func storageId() -> String { "fixture-storage" }
}

private final class DelayedConnectSession: RemoteSession {
    var gate: DispatchSemaphore?
    var onProbe: (() -> Void)?
    var passwordGate: DispatchSemaphore?
    var onPassword: (() -> Void)?
    override func passwordLogin(connection: PreparedConnectionFfi, email: String, password: String,
                                operation: SessionOperationFfi) throws -> SessionAccessFfi {
        onPassword?()
        if let passwordGate, passwordGate.wait(timeout: .now() + 5) != .success {
            throw CoreError.Service("fixture password gate timed out")
        }
        throw CoreError.Session(kind: .cancelled, message: "fixture cancelled")
    }
    override func prepareConnection(endpoint: String, connectionName: String, profileName: String) throws -> PrepareConnectionOutcomeFfi {
        onProbe?()
        if let gate, gate.wait(timeout: .now() + 5) != .success {
            throw CoreError.Service("fixture probe gate timed out")
        }
        return .ready(connection: ConnectPreparedFixture(noPointer: .init()))
    }
}

private final class ConnectFixtureCore: CoreFacade {
    private var connectSession: RemoteSession?
    convenience init(wrapping core: CoreFacade, session: RemoteSession) {
        self.init(unsafeFromRawPointer: core.uniffiClonePointer())
        connectSession = session
    }
    override func remoteSession() throws -> RemoteSession {
        guard let connectSession else { throw CoreError.Service("missing fixture session") }
        return connectSession
    }
}

@MainActor
final class ConnectFlowAdapterTests: XCTestCase {
    private func model(_ session: RemoteSession) -> ConnectModel {
        ConnectModel(session: session, strings: Strings(language: "en"),
                     openBrowser: { _ in XCTFail("unexpected browser effect") },
                     copyBrowserUrl: { _ in XCTFail("unexpected copy effect") },
                     connected: { _ in XCTFail("unexpected navigation effect") })
    }

    func testLateProbeCannotInstallCapabilitiesAfterCancelOrReopen() async {
        let session = DelayedConnectSession(noPointer: .init())
        let gate = DispatchSemaphore(value: 0)
        let started = expectation(description: "probe started off the main actor")
        session.gate = gate
        session.onProbe = { started.fulfill() }
        let old = model(session)
        old.url = "https://old.example.test"
        let pending = Task { await old.probe() }
        await fulfillment(of: [started], timeout: 2)
        old.cancel()
        let reopened = model(DelayedConnectSession(noPointer: .init()))
        gate.signal()
        await pending.value
        XCTAssertEqual(old.stage, .closed)
        XCTAssertNil(old.serverName)
        XCTAssertNil(old.error)
        XCTAssertEqual(reopened.stage, .server)
        XCTAssertNil(reopened.serverName)
        XCTAssertFalse(reopened.busy)
    }

    func testRootReplacementCancelsThePreviousAdapterBeforeInstallingANewOne() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let keystore = MemoryKeystore()
        let native = try createCore(dbPath: directory.appendingPathComponent("local.sqlite").path,
                                    keystore: keystore, secretStore: MemorySecretStore())
        let session = DelayedConnectSession(noPointer: .init())
        let core = ConnectFixtureCore(wrapping: native, session: session)
        let app = AppModel(opening: { (core, keystore) },
                           preferences: { PreferencesFile(url: directory.appendingPathComponent("preferences.json")) },
                           systemLanguage: "en", openBrowser: { _ in XCTFail("unexpected browser") })
        let gate = DispatchSemaphore(value: 0)
        let started = expectation(description: "old root probe started")
        session.gate = gate
        session.onProbe = { started.fulfill() }
        app.startConnecting(serverURL: "https://old.example.test")
        let old = try XCTUnwrap(app.connect)
        let pending = Task { await old.probe() }
        await fulfillment(of: [started], timeout: 2)
        app.startConnecting(serverURL: "https://new.example.test")
        let reopened = try XCTUnwrap(app.connect)
        gate.signal()
        await pending.value
        XCTAssertEqual(old.stage, .closed)
        XCTAssertTrue(app.connect === reopened)
        XCTAssertEqual(reopened.stage, .server)
        XCTAssertEqual(reopened.url, "https://new.example.test")
    }

    func testAdapterRendersSharedRegistrationAndBackTransitions() async {
        let connect = model(DelayedConnectSession(noPointer: .init()))
        connect.url = "https://fixture.example.test"
        await connect.probe()
        XCTAssertEqual(connect.stage, .password(register: false))
        XCTAssertTrue(connect.registrationAvailable)
        connect.setRegistering(true)
        XCTAssertEqual(connect.stage, .password(register: true))
        XCTAssertTrue(connect.back())
        XCTAssertEqual(connect.stage, .server)
        XCTAssertFalse(connect.back())
        XCTAssertEqual(connect.stage, .closed)
    }

    func testBusyAdmissionPreservesANewPasswordDraft() async {
        let session = DelayedConnectSession(noPointer: .init())
        let connect = model(session)
        connect.url = "https://fixture.example.test"
        connect.email = "person@example.test"
        await connect.probe()
        XCTAssertTrue(connect.canSubmitPassword("new-draft"))
        let gate = DispatchSemaphore(value: 0)
        let started = expectation(description: "password request started")
        session.passwordGate = gate
        session.onPassword = { started.fulfill() }
        let pending = Task { await connect.submitPassword("in-flight") }
        await fulfillment(of: [started], timeout: 2)
        XCTAssertFalse(connect.canSubmitPassword("new-draft"), "the view must not clear a rejected draft")
        connect.cancel()
        gate.signal()
        await pending.value
        XCTAssertNil(connect.error)
    }

    func testSwiftDiagnosticsRedactForeignEnumPayloads() {
        let secret = "swift-debug-secret-sentinel"
        let id = ConnectOperationFfi(instance: 1, sequence: 1)
        let action = ConnectActionFfi.submitPassword(email: "person@example.test", password: secret, fullName: nil)
        let effect = ConnectEffectFfi.password(id: id, email: "person@example.test", password: secret,
                                             fullName: nil, register: false, timeoutMs: 1)
        XCTAssertFalse(String(reflecting: action).contains(secret))
        XCTAssertFalse(String(reflecting: effect).contains(secret))
        XCTAssertFalse(String(reflecting: ConnectStageFfi.browser(url: secret)).contains(secret))
    }
}
