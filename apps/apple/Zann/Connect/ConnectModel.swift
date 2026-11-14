import Foundation
import ZannCoreKit

/// Form and effect adapter for the same reducer COSMIC consumes directly.
/// Prepared connections and trust/browser capabilities stay opaque and local.
@MainActor
final class ConnectModel: ObservableObject {
    typealias Stage = ConnectStageFfi
    struct Connected: Equatable { let hasPersonalKeys: Bool }

    @Published var url = ""
    @Published var email = ""
    @Published var fullName = ""
    @Published private var snapshot: ConnectSnapshotFfi
    var stage: Stage { snapshot.stage }
    var busy: Bool { snapshot.busy }
    var error: String? { snapshot.error }
    var methods: [AuthMethodFfi] { snapshot.methods }
    var registrationAvailable: Bool { snapshot.registrationAvailable }
    var serverName: String? { snapshot.serverName }

    private let flow: ConnectFlowFfi
    private let session: RemoteSession
    private let strings: Strings
    private let openBrowser: (URL) -> Void
    private let copyBrowserUrl: (String) -> Void
    private let connected: (Connected) -> Void
    private var connection: PreparedConnectionFfi?
    private var challenge: ConnectionTrustChallengeFfi?
    private var browser: OidcLoginFfi?
    private var operation: (ConnectOperationFfi, SessionOperationFfi)?

    init(session: RemoteSession, strings: Strings, openBrowser: @escaping (URL) -> Void,
         copyBrowserUrl: @escaping (String) -> Void, connected: @escaping (Connected) -> Void) {
        let flow = ConnectFlowFfi()
        self.flow = flow
        self.copyBrowserUrl = copyBrowserUrl
        self.session = session
        self.strings = strings
        self.openBrowser = openBrowser
        self.connected = connected
        self.snapshot = flow.snapshot()
    }

    deinit { operation?.1.cancel() }

    func probe() async { await perform(flow.dispatch(action: .probe(url: url))) }
    func trustFingerprint() async { await perform(flow.dispatch(action: .trustFingerprint)) }
    func canSubmitPassword(_ password: String) -> Bool {
        flow.canSubmitPassword(email: email, password: password)
    }
    func submitPassword(_ password: String) async {
        await perform(flow.dispatch(action: .submitPassword(email: email, password: password, fullName: fullName)))
    }
    func signInWithBrowser() async { await perform(flow.dispatch(action: .startOidc)) }
    func choosePassword() { send(.choosePassword) }
    func setRegistering(_ register: Bool) { send(.setRegistering(register: register)) }
    func reopenBrowser() { send(.reopenBrowser) }
    func copyBrowserLink() { send(.copyBrowserUrl) }
    func cancel() { send(.cancel) }
    func back() -> Bool {
        send(.back)
        return stage != .closed
    }

    private func send(_ action: ConnectActionFfi) {
        for work in consume(flow.dispatch(action: action)) {
            Task { await execute(work) }
        }
    }

    /// Apply state and OS effects on the UI actor, before yielding to any task.
    private func consume(_ effects: [ConnectEffectFfi]) -> [ConnectEffectFfi] {
        snapshot = flow.snapshot()
        var work: [ConnectEffectFfi] = []
        for effect in effects {
            switch effect {
            case .cancel(let id):
                if operation?.0 == id { operation?.1.cancel(); operation = nil; browser = nil }
            case .resetConnection:
                connection = nil; challenge = nil; browser = nil
            case .openBrowser(let id, let value):
                // The canonical OIDC owner validates the authorization URL.
                if let url = URL(string: value) {
                    openBrowser(url)
                } else {
                    let message = strings.message(for: CoreError.InvalidArgument("invalid browser URL"))
                    _ = consume(flow.complete(completion: .failed(id: id, step: .oidcFinish, message: message)))
                }
            case .copyBrowserUrl(_, let value):
                copyBrowserUrl(value)
            case .connected(_, let hasKeys):
                connected(Connected(hasPersonalKeys: hasKeys))
            case .closed:
                break // The shell's Back action observes the terminal snapshot.
            case .probe, .trustFingerprint, .password, .beginOidc, .finishOidc:
                work.append(effect)
            }
        }
        return work
    }

    private func perform(_ effects: [ConnectEffectFfi]) async {
        for work in consume(effects) { await execute(work) }
    }

    private func execute(_ effect: ConnectEffectFfi) async {
        switch effect {
        case .probe(let id, let endpoint, let connectionName, let profileName):
            guard flow.accepts(id: id, step: .probe) else { return }
            let session = session
            await run(id, .probe, {
                try session.prepareConnection(endpoint: endpoint, connectionName: connectionName, profileName: profileName)
            }) { outcome in
                switch outcome {
                case .ready(let connection):
                    self.connection = connection
                    return .probed(id: id, probe: .ready(info: self.info(connection)))
                case .fingerprintChanged(let challenge):
                    self.challenge = challenge
                    return .probed(id: id, probe: .fingerprintChanged(old: challenge.oldFingerprint(), new: challenge.newFingerprint()))
                }
            }
        case .trustFingerprint(let id):
            guard flow.accepts(id: id, step: .trust) else { return }
            guard let challenge else { await fail(id, .trust, CoreError.InvalidArgument("missing fingerprint challenge")); return }
            let session = session
            await run(id, .trust, { try session.trustConnection(challenge: challenge) }) { connection in
                self.challenge = nil
                self.connection = connection
                return .trusted(id: id, info: self.info(connection))
            }
        case .password(let id, let email, let password, let fullName, let register, let timeout):
            guard flow.accepts(id: id, step: .password) else { return }
            guard let connection else { await fail(id, .password, CoreError.InvalidArgument("missing prepared connection")); return }
            guard let operation = await newOperation(id, .password, timeout) else { return }
            let session = session
            await run(id, .password, {
                let access = register
                    ? try session.passwordRegister(connection: connection, email: email, password: password, fullName: fullName, operation: operation)
                    : try session.passwordLogin(connection: connection, email: email, password: password, operation: operation)
                return try session.personalVaultStatus(access: access).personalKeyEnvelopesPresent
            }) { .password(id: id, storageId: connection.storageId(), hasPersonalKeys: $0) }
        case .beginOidc(let id, let timeout):
            guard flow.accepts(id: id, step: .oidcStart) else { return }
            guard let connection else { await fail(id, .oidcStart, CoreError.InvalidArgument("missing prepared connection")); return }
            guard let operation = await newOperation(id, .oidcStart, timeout) else { return }
            let session = session
            await run(id, .oidcStart, { try session.beginOidcLogin(connection: connection, operation: operation) }) { login in
                self.browser = login
                return .oidcStarted(id: id, url: login.authorizationUrl())
            }
        case .finishOidc(let id):
            guard flow.accepts(id: id, step: .oidcFinish) else { return }
            guard let browser, let connection else { await fail(id, .oidcFinish, CoreError.InvalidArgument("missing browser login")); return }
            let session = session
            await run(id, .oidcFinish, { try session.personalVaultStatus(access: browser.finish()).personalKeyEnvelopesPresent }) {
                .oidcFinished(id: id, storageId: connection.storageId(), hasPersonalKeys: $0)
            }
        default:
            preconditionFailure("only work effects reach the executor")
        }
    }

    private func newOperation(_ id: ConnectOperationFfi, _ step: ConnectStepFfi, _ timeout: UInt64) async -> SessionOperationFfi? {
        do {
            let operation = try SessionOperationFfi(timeoutMs: timeout)
            self.operation = (id, operation)
            return operation
        } catch { await fail(id, step, error); return nil }
    }

    /// Actor serialization makes the ID check, capability install and reducer
    /// completion atomic relative to Back/Cancel and subsequent user actions.
    private func run<T>(_ id: ConnectOperationFfi, _ step: ConnectStepFfi,
                        _ work: @escaping () throws -> T,
                        _ complete: (T) -> ConnectCompletionFfi) async {
        guard flow.accepts(id: id, step: step) else { return }
        let result = await Task.detached(priority: .userInitiated) { Result(catching: work) }.value
        guard flow.accepts(id: id, step: step) else { return }
        switch result {
        case .success(let value): await perform(flow.complete(completion: complete(value)))
        case .failure(let error): await fail(id, step, error)
        }
    }

    private func fail(_ id: ConnectOperationFfi, _ step: ConnectStepFfi, _ error: Error) async {
        let message: String?
        switch error {
        case CoreError.Session(.cancelled, _), CoreError.Oidc(.cancelled, _): message = nil
        default: message = strings.message(for: error)
        }
        await perform(flow.complete(completion: .failed(id: id, step: step, message: message)))
    }

    private func info(_ connection: PreparedConnectionFfi) -> ConnectServerFfi {
        ConnectServerFfi(methods: connection.authMethods(), registrationAvailable: connection.registrationAvailable(), serverName: connection.serverName())
    }
}
