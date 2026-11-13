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
        case connect
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
    /// Whether Touch ID can open the vault without the master password.
    @Published private(set) var touchIDArmed = false
    /// An arm or disarm is running; the settings toggle waits for it.
    @Published private(set) var touchIDBusy = false
    /// The server sign-in in progress, present only on the connect screen.
    @Published private(set) var connect: ConnectModel?
    /// Where leaving the connect screen goes: the welcome screen for a new
    /// device, the unlock screen after forgetting a server.
    private var connectReturn = Screen.welcome
    /// A fresh sign-in follows its server after the first background sync.
    /// The cached vault UI opens as soon as the master key is verified.
    @Published private(set) var syncAfterUnlock = false

    private let core: CoreFacade?
    /// The keystore the core was composed with; asked for its status only,
    /// which never prompts.
    private let keystore: DeviceKeystore?
    private let preferencesFile: PreferencesFile?
    private let systemLanguage: String
    private let openBrowser: (URL) -> Void
    /// The last input the app received while unlocked; the idle lock counts
    /// from here, as COSMIC's does.
    private var lastActivity = Date()

    /// The composition root: the app passes `openDefaultCore`,
    /// `defaultPreferencesFile` and the system browser, tests a core over a
    /// temporary database, in-memory ports, a temporary preferences file and
    /// a recorder.
    init(
        opening open: () throws -> (core: CoreFacade, keystore: DeviceKeystore),
        preferences file: () throws -> PreferencesFile,
        systemLanguage: String,
        openBrowser: @escaping (URL) -> Void
    ) {
        self.systemLanguage = systemLanguage
        self.openBrowser = openBrowser
        var opened: (core: CoreFacade, keystore: DeviceKeystore)?
        var openedFile: PreferencesFile?
        var armed = false
        var rememberedError: Error?
        // Placeholders for the failure screen only; nothing reads them there.
        var loaded = devicePreferencesDefault()
        do {
            let preferencesFile = try file()
            loaded = try preferencesFile.load()
            let composed = try open()
            screen = try composed.core.appStatus().initialized ? .master(.unlock) : .welcome
            // An unreadable remembered unlock must not block the password: it
            // shows on the unlock screen and Touch ID stays off.
            do {
                armed = try Self.touchIDArmed(composed.core)
            } catch {
                rememberedError = error
            }
            openedFile = preferencesFile
            opened = composed
        } catch {
            screen = .failed(describe(error))
        }
        preferences = loaded
        strings = Strings(language: loaded.language ?? systemLanguage)
        preferencesFile = openedFile
        core = opened?.core
        keystore = opened?.keystore
        touchIDArmed = armed
        keystore?.setPromptReason(strings("unlock.touchIdReason"))
        if let rememberedError {
            error = message(for: rememberedError)
        }
    }

    /// What Touch ID can do on this device right now; never prompts.
    var keystoreStatus: PlatformKeystoreStatus? {
        keystore?.status()
    }

    /// Prompts for Touch ID; dismissing the prompt leaves no error behind.
    func unlockWithTouchID() async {
        guard let core, !busy, touchIDArmed else { return }
        let contents = await perform {
            _ = try core.unlockRemembered()
            return try VaultModel.load(core)
        }
        if let contents {
            open(core: core, contents: contents)
        } else if case .Unlock("keystore_cancelled", _)? = lastFailure as? CoreError {
            error = nil
        }
    }

    /// Arms or disarms Touch ID, one change at a time so a quick on-then-off
    /// cannot interleave the keychain and `unlock.json` writes. Arming needs
    /// the vault unlocked, because the core wraps the master key it holds;
    /// disarming works any time, so a device without Touch ID can still
    /// revoke it.
    func setTouchID(_ enabled: Bool) async {
        guard let core, !touchIDBusy, !enabled || isUnlocked else { return }
        touchIDBusy = true
        defer { touchIDBusy = false }
        settingsError = nil
        let result = await Task.detached(priority: .userInitiated) {
            Result {
                if enabled {
                    try core.rememberWithKeystore()
                } else {
                    try core.forgetRemembered()
                }
                return try Self.touchIDArmed(core)
            }
        }.value
        switch result {
        case .success(let armed): touchIDArmed = armed
        case .failure(let failure): settingsError = message(for: failure)
        }
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
            keystore?.setPromptReason(strings("unlock.touchIdReason"))
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

    /// `serverURL` prefills the address, as after forgetting a server.
    func startConnecting(serverURL: String? = nil, returnTo: Screen = .welcome) {
        guard let core else { return }
        error = nil
        let session: RemoteSession
        do {
            session = try core.remoteSession()
        } catch {
            self.error = message(for: error)
            return
        }
        connect = ConnectModel(
            session: session, strings: strings, openBrowser: openBrowser,
            connected: { [weak self] in self?.connected($0) }
        )
        if let serverURL {
            connect?.url = serverURL
        }
        connectReturn = returnTo
        screen = .connect
    }

    /// Back from the connect screen's first step, or away from it entirely.
    func leaveConnecting() {
        connect?.cancel()
        connect = nil
        screen = connectReturn
    }

    /// Forgets the server whose identity changed, with its pinned identity
    /// and stored sign-in; the vault's items and unsent changes stay on this
    /// Mac. The vault locks, since signing in again ends at the master
    /// password, and the connect screen opens at the forgotten address.
    func forgetStaleServer() async {
        guard let core, let stale = vault?.staleServer, !busy else { return }
        let storageID = stale.storageID
        await reconnect { try core.forgetServer(storageId: storageID) }
    }

    /// Connects again to the server of a vault whose connection is gone;
    /// connecting with the same account takes the vault and its unsent
    /// changes over. Like forgetting a server, it locks the vault first.
    func reconnectServer() async {
        guard let gone = vault?.disconnected, !busy else { return }
        let serverURL = gone.serverURL
        await reconnect { serverURL }
    }

    /// Locks the vault, since connecting ends at the master password, and
    /// opens the connect screen at the address `address` returns.
    private func reconnect(_ address: @escaping () throws -> String?) async {
        guard let core else { return }
        vault?.stopAutoSync()
        guard let serverURL = await perform({ () -> String? in
            let serverURL = try address()
            _ = try core.lock()
            return serverURL
        }) else {
            vault?.startAutoSync()
            return
        }
        vault = nil
        if preferences.clipboardClearOnLock {
            Clipboard.clearOwned()
        }
        startConnecting(serverURL: serverURL, returnTo: .master(.unlock))
    }

    /// The account's existing personal vault opens with its master password;
    /// a new account creates one.
    func connected(_ outcome: ConnectModel.Connected) {
        guard screen == .connect else { return }
        connect = nil
        syncAfterUnlock = true
        screen = .master(outcome.hasPersonalKeys ? .unlock : .create)
    }

    func submit(password: String, mode: MasterMode) async {
        guard let core, !busy, !password.isEmpty else { return }
        let contents = await perform {
            switch mode {
            case .create: _ = try core.initializeMasterPassword(password: password)
            case .unlock: _ = try core.unlock(password: password)
            }
            return try VaultModel.load(core)
        }
        guard let contents else { return }
        open(core: core, contents: contents)
    }

    /// Open cached content immediately; even the first server sync runs behind
    /// the usable vault UI. The core still owns preferred-storage selection.
    private func open(core: CoreFacade, contents: VaultModel.Contents) {
        let vault = VaultModel(core: core, contents: contents, strings: strings,
                               followAfterSync: syncAfterUnlock)
        syncAfterUnlock = false
        self.vault = vault
        lastActivity = Date()
        screen = .vault
        vault.startAutoSync()
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
        // Stopped first, so no tick admits a sync while the core locks; the
        // core's lock cancels one already running.
        vault?.stopAutoSync()
        guard await perform({ _ = try core.lock() }) != nil else { return }
        vault = nil
        if preferences.clipboardClearOnLock {
            Clipboard.clearOwned()
        }
        screen = .master(.unlock)
    }

    /// The failure behind the last `nil` from `perform`.
    private var lastFailure: Error?

    /// Runs `work` off the main actor; a failure lands in `error` as `nil`.
    private func perform<T>(_ work: @escaping () throws -> T) async -> T? {
        busy = true
        error = nil
        lastFailure = nil
        defer { busy = false }
        let result = await Task.detached(priority: .userInitiated) {
            Result(catching: work)
        }.value
        switch result {
        case .success(let value):
            return value
        case .failure(let failure):
            lastFailure = failure
            error = message(for: failure)
            return nil
        }
    }

    private func message(for failure: Error) -> String {
        strings.message(for: failure)
    }

    private nonisolated static func touchIDArmed(_ core: CoreFacade) throws -> Bool {
        let remembered = try core.rememberedUnlock()
        return remembered.armed && remembered.source == "keystore"
    }

    /// The database lives under Application Support in a directory named after
    /// the bundle, apart from the Tauri desktop app's. The Touch ID reason is
    /// set by `AppModel` once it knows the language.
    static func openDefaultCore() throws -> (core: CoreFacade, keystore: DeviceKeystore) {
        let keystore = KeychainKeystore(service: try Self.bundleID(), promptReason: "")
        let core = try createCore(
            dbPath: try Self.dataDirectory().appendingPathComponent("local.sqlite").path,
            keystore: keystore,
            secretStore: KeychainSecretStore()
        )
        return (core, keystore)
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
    case .Cancelled:
        return "Operation cancelled."
    case .DeadlineExceeded:
        return "The operation timed out."
    case .InvalidArgument(let message), .Service(let message), .Unimplemented(let message):
        return message
    case .Unlock(_, let message), .Sync(_, let message):
        return message
    case .Session(_, let message), .Oidc(_, let message), .Draft(_, _, let message):
        return message
    }
}
