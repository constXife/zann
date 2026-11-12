import Foundation
import ZannCoreKit

/// Long enough to finish a browser sign-in, as COSMIC allows.
private let loginTimeoutMs: UInt64 = 10 * 60 * 1000

/// Connecting this Mac to a server: probe and pin the server, confirm a
/// changed fingerprint, then sign in with a password or the browser. Trust
/// pinning, credential custody and the session itself stay in the core's
/// `RemoteSession`; this type only sequences its blocking calls.
@MainActor
final class ConnectModel: ObservableObject {
    enum Stage: Equatable {
        case server
        case fingerprint(old: String, new: String)
        case methods
        case password(register: Bool)
        case browser(url: URL)
    }

    /// Whether the signed-in account already has a personal vault to open
    /// with the master password.
    struct Connected: Equatable {
        let hasPersonalKeys: Bool
    }

    @Published var url = ""
    @Published var email = ""
    @Published var fullName = ""
    @Published private(set) var stage = Stage.server
    @Published private(set) var busy = false
    @Published private(set) var error: String?
    @Published private(set) var methods: [AuthMethodFfi] = []
    @Published private(set) var registrationAvailable = false
    @Published private(set) var serverName: String?

    private let session: RemoteSession
    private let strings: Strings
    private let openBrowser: (URL) -> Void
    private let connected: (Connected) -> Void
    private var connection: PreparedConnectionFfi?
    private var challenge: ConnectionTrustChallengeFfi?
    /// The sign-in in flight, so leaving its stage cancels it.
    private var operation: SessionOperationFfi?
    /// Bumped whenever the user leaves a step, so a call that completes
    /// afterwards, even successfully, changes nothing.
    private var generation = 0

    init(
        session: RemoteSession,
        strings: Strings,
        openBrowser: @escaping (URL) -> Void,
        connected: @escaping (Connected) -> Void
    ) {
        self.session = session
        self.strings = strings
        self.openBrowser = openBrowser
        self.connected = connected
    }

    /// Verifies the server's signed identity and pins it on first use.
    func probe() async {
        let endpoint = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !busy, !endpoint.isEmpty else { return }
        let session = session
        let outcome = await run {
            try session.prepareConnection(
                endpoint: endpoint, connectionName: "Remote", profileName: "default"
            )
        }
        switch outcome {
        case .ready(let connection)?:
            offer(connection)
        case .fingerprintChanged(let challenge)?:
            self.challenge = challenge
            stage = .fingerprint(old: challenge.oldFingerprint(), new: challenge.newFingerprint())
        case nil:
            break
        }
    }

    /// The user accepts the server's new key; it replaces the pinned one.
    func trustFingerprint() async {
        guard let challenge else { return }
        let session = session
        guard let connection = await run({ try session.trustConnection(challenge: challenge) })
        else { return }
        self.challenge = nil
        offer(connection)
    }

    func choosePassword() {
        error = nil
        stage = .password(register: false)
    }

    func setRegistering(_ register: Bool) {
        guard case .password = stage, !busy else { return }
        error = nil
        stage = .password(register: register && registrationAvailable)
    }

    func submitPassword(_ password: String) async {
        guard let connection, case .password(let register) = stage, !busy, !password.isEmpty
        else { return }
        let account = email.trimmingCharacters(in: .whitespacesAndNewlines)
        let name = fullName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !account.isEmpty, let operation = newOperation() else { return }
        let session = session
        let result = await run { () -> Connected in
            let access = register
                ? try session.passwordRegister(
                    connection: connection, email: account, password: password,
                    fullName: name.isEmpty ? nil : name, operation: operation
                )
                : try session.passwordLogin(
                    connection: connection, email: account, password: password,
                    operation: operation
                )
            return try Self.outcome(session, access)
        }
        if let result { connected(result) }
    }

    /// Opens the server's sign-in page and waits for the browser to come back.
    func signInWithBrowser() async {
        guard let connection, !busy, let operation = newOperation() else { return }
        let session = session
        guard let login = await run({
            try session.beginOidcLogin(connection: connection, operation: operation)
        }) else { return }
        // The core admits only https, or http to a loopback address.
        guard let url = URL(string: login.authorizationUrl()) else {
            operation.cancel()
            error = describe(CoreError.InvalidArgument("the server sent an invalid sign-in URL"))
            return
        }
        stage = .browser(url: url)
        openBrowser(url)
        let result = await run { () -> Connected in
            try Self.outcome(session, try login.finish())
        }
        if let result { connected(result) }
    }

    func reopenBrowser() {
        if case .browser(let url) = stage { openBrowser(url) }
    }

    /// One step back; from the first step the caller leaves the flow.
    /// Returns whether a step remained to go back to.
    func back() -> Bool {
        cancel()
        error = nil
        switch stage {
        case .server:
            return false
        case .fingerprint, .methods:
            challenge = nil
            connection = nil
            stage = .server
        case .password, .browser:
            stage = methods.count > 1 ? .methods : .server
        }
        return true
    }

    /// Leaving the flow cancels a sign-in that is still waiting and
    /// discards whatever a running call returns.
    func cancel() {
        operation?.cancel()
        operation = nil
        generation += 1
        busy = false
    }

    private func offer(_ connection: PreparedConnectionFfi) {
        let interactive = connection.authMethods().filter { $0 == .password || $0 == .oidc }
        guard !interactive.isEmpty else {
            error = describe(CoreError.InvalidArgument("the server offers no way to sign in here"))
            stage = .server
            return
        }
        self.connection = connection
        methods = interactive
        registrationAvailable = connection.registrationAvailable()
        serverName = connection.serverName()
        if interactive == [.password] {
            stage = .password(register: false)
        } else if interactive == [.oidc] {
            stage = .methods
            Task { await signInWithBrowser() }
        } else {
            stage = .methods
        }
    }

    private func newOperation() -> SessionOperationFfi? {
        do {
            let operation = try SessionOperationFfi(timeoutMs: loginTimeoutMs)
            self.operation = operation
            return operation
        } catch {
            self.error = strings.message(for: error)
            return nil
        }
    }

    /// Runs `work` off the main actor. A call the user left behind returns
    /// `nil`, and so does a cancelled sign-in: neither is an error.
    private func run<T>(_ work: @escaping () throws -> T) async -> T? {
        let started = generation
        busy = true
        error = nil
        let result = await Task.detached(priority: .userInitiated) {
            Result(catching: work)
        }.value
        guard started == generation else { return nil }
        busy = false
        switch result {
        case .success(let value):
            return value
        case .failure(CoreError.Session(.cancelled, _)), .failure(CoreError.Oidc(.cancelled, _)):
            return nil
        case .failure(let failure):
            error = strings.message(for: failure)
            return nil
        }
    }

    private nonisolated static func outcome(
        _ session: RemoteSession, _ access: SessionAccessFfi
    ) throws -> Connected {
        let status = try session.personalVaultStatus(access: access)
        return Connected(hasPersonalKeys: status.personalKeyEnvelopesPresent)
    }
}
