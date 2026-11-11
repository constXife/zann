import Foundation
import ZannCoreKit

/// Screen state for the macOS shell. Every core call blocks (the KDF alone
/// takes about a second), so it runs off the main actor; this type only
/// sequences calls and publishes their results.
@MainActor
final class AppModel: ObservableObject {
    enum Screen: Equatable {
        case failed(String)
        case welcome
        case master(MasterMode)
        case vault
    }

    enum MasterMode {
        case create
        case unlock
    }

    @Published private(set) var screen: Screen
    /// Present only while unlocked; locking drops it with every secret it holds.
    @Published private(set) var vault: VaultModel?
    @Published private(set) var busy = false
    @Published private(set) var error: String?

    let strings: Strings
    /// Defaults until the shell persists device preferences.
    let preferences = devicePreferencesDefault()
    private let core: CoreFacade?

    /// `open` is the composition root: the app passes `openDefaultCore`,
    /// tests a core over a temporary database and in-memory ports.
    init(opening open: () throws -> CoreFacade, language: String) {
        strings = Strings(language: language)
        var opened: CoreFacade?
        do {
            let core = try open()
            screen = try core.appStatus().initialized ? .master(.unlock) : .welcome
            opened = core
        } catch {
            screen = .failed(describe(error))
        }
        core = opened
    }

    var isUnlocked: Bool {
        screen == .vault
    }

    func startCreatingVault() {
        error = nil
        screen = .master(.create)
    }

    func submit(password: String, mode: MasterMode) async {
        guard let core, !busy, !password.isEmpty else { return }
        let page = await perform {
            switch mode {
            case .create: _ = try core.initializeMasterPassword(password: password)
            case .unlock: _ = try core.unlock(password: password)
            }
            return try VaultModel.loadPage(core)
        }
        guard let page else { return }
        vault = VaultModel(core: core, page: page)
        screen = .vault
    }

    func lock() async {
        guard let core, isUnlocked, !busy else { return }
        guard await perform({ _ = try core.lock() }) != nil else { return }
        vault = nil
        if preferences.clipboardClearOnLock {
            Clipboard.clearOwned()
        }
        screen = .master(.unlock)
    }

    /// Runs `work` off the main actor; a failure lands in `error` as `nil`.
    private func perform<T>(_ work: @escaping () throws -> T) async -> T? {
        busy = true
        error = nil
        defer { busy = false }
        let result = await Task.detached(priority: .userInitiated) {
            Result(catching: work)
        }.value
        switch result {
        case .success(let value):
            return value
        case .failure(let failure):
            error = describe(failure)
            return nil
        }
    }

    /// The database lives under Application Support in a directory named after
    /// the bundle, apart from the Tauri desktop app's.
    static func openDefaultCore() throws -> CoreFacade {
        guard let bundleID = Bundle.main.bundleIdentifier else {
            throw CoreError.InvalidArgument("the app bundle has no identifier")
        }
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        )
        let database = support.appendingPathComponent(bundleID, isDirectory: true)
            .appendingPathComponent("local.sqlite")
        return try createCore(
            dbPath: database.path,
            keystore: KeychainKeystore(service: bundleID),
            secretStore: KeychainSecretStore()
        )
    }
}

/// The core's own message for an error, without the enum wrapping.
func describe(_ error: Error) -> String {
    guard let error = error as? CoreError else {
        return error.localizedDescription
    }
    switch error {
    case .Locked:
        return "The vault is locked."
    case .InvalidArgument(let message), .Service(let message), .Unimplemented(let message):
        return message
    case .Unlock(_, let message), .Sync(_, let message):
        return message
    case .Session(_, let message), .Oidc(_, let message), .Draft(_, _, let message):
        return message
    }
}
