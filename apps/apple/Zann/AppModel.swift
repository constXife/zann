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
    /// Read from the preferences file; the settings window edits them.
    @Published private(set) var preferences: DevicePreferencesFfi
    /// The catalogue in the preferred language, or the system's.
    @Published private(set) var strings: Strings
    /// Why the last settings change could not be saved.
    @Published private(set) var settingsError: String?

    private let core: CoreFacade?
    private let preferencesFile: PreferencesFile?
    private let systemLanguage: String
    /// The last input the app received while unlocked; the idle lock counts
    /// from here, as COSMIC's does.
    private var lastActivity = Date()

    /// The composition root: the app passes `openDefaultCore` and
    /// `defaultPreferencesFile`, tests a core over a temporary database,
    /// in-memory ports and a temporary preferences file.
    init(
        opening open: () throws -> CoreFacade,
        preferences file: () throws -> PreferencesFile,
        systemLanguage: String
    ) {
        self.systemLanguage = systemLanguage
        var opened: CoreFacade?
        var openedFile: PreferencesFile?
        // Placeholders for the failure screen only; nothing reads them there.
        var loaded = devicePreferencesDefault()
        do {
            let preferencesFile = try file()
            loaded = try preferencesFile.load()
            let core = try open()
            screen = try core.appStatus().initialized ? .master(.unlock) : .welcome
            openedFile = preferencesFile
            opened = core
        } catch {
            screen = .failed(describe(error))
        }
        preferences = loaded
        strings = Strings(language: loaded.language ?? systemLanguage)
        preferencesFile = openedFile
        core = opened
    }

    /// Applies one settings change and saves it; the change takes effect only
    /// once it is on disk.
    func updatePreferences(_ change: (inout DevicePreferencesFfi) -> Void) {
        guard let preferencesFile else { return }
        var next = preferences
        change(&next)
        guard next != preferences else { return }
        do {
            try preferencesFile.save(next)
        } catch {
            settingsError = describe(error)
            return
        }
        settingsError = nil
        if next.language != preferences.language {
            strings = Strings(language: next.language ?? systemLanguage)
        }
        preferences = next
    }

    /// The app is quitting; values it put on the clipboard go with it.
    func appWillTerminate() {
        if preferences.clipboardClearOnExit {
            Clipboard.clearOwned()
        }
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
        lastActivity = Date()
        screen = .vault
    }

    func noteActivity(at now: Date = Date()) {
        lastActivity = now
    }

    /// Locks once `auto_lock_minutes` pass without input; `0` disables it.
    func checkIdle(at now: Date = Date()) async {
        let minutes = preferences.autoLockMinutes
        guard isUnlocked, minutes > 0,
              now.timeIntervalSince(lastActivity) >= TimeInterval(minutes) * 60
        else { return }
        await lock()
    }

    func appResignedActive() async {
        if preferences.lockOnFocusLoss {
            await lock()
        }
    }

    /// The app was hidden, or its window minimized or closed.
    func appHidden() async {
        if preferences.lockOnHidden {
            await lock()
        }
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
        let bundleID = try Self.bundleID()
        return try createCore(
            dbPath: try Self.dataDirectory().appendingPathComponent("local.sqlite").path,
            keystore: KeychainKeystore(service: bundleID),
            secretStore: KeychainSecretStore()
        )
    }

    /// Beside the database, so one directory holds all of this app's state.
    static func defaultPreferencesFile() throws -> PreferencesFile {
        PreferencesFile(url: try dataDirectory().appendingPathComponent("preferences.json"))
    }

    private static func dataDirectory() throws -> URL {
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        )
        return support.appendingPathComponent(try bundleID(), isDirectory: true)
    }

    private static func bundleID() throws -> String {
        guard let bundleID = Bundle.main.bundleIdentifier else {
            throw CoreError.InvalidArgument("the app bundle has no identifier")
        }
        return bundleID
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
