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
        case accounts
        case master(MasterMode)
        case vault
    }

    typealias MasterMode = UnlockPhaseFfi

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
    private var connectedAccountHasKeys: Bool?
    private var pendingStorage: String?
    @Published private(set) var recovery: RecoveryModel?
    @Published private(set) var enrollmentAccount: SetupAccountFfi?
    @Published private(set) var deviceUnlocked = false
    private let unlockOperations = UnlockOperationsFfi()
    private var connectReturn = Screen.welcome
    /// A fresh sign-in explains that the first catalog arrives after unlock.
    /// The cached vault UI opens as soon as the master key is verified.
    @Published private(set) var syncAfterUnlock = false

    private let core: CoreFacade?
    var browserCore: CoreFacade? { core }
    /// The keystore the core was composed with; asked for its status only,
    /// which never prompts.
    private let keystore: DeviceKeystore?
    private let preferencesFile: PreferencesFile?
    private let systemLanguage: String
    private let browser: BrowserAuthorization
    private var pendingCoreWork: Task<Void, Never>?
    private var logoutOperation: SessionOperationFfi?
    /// One prompt for the launch unlock screen, never for a later lock.
    private var startupTouchIDPending = false
    private var platformUnlockPending = false
    private var pendingConnection: ConnectModel.Connected?
    /// The last input the app received while unlocked; the idle lock counts
    /// from here, as COSMIC's does.
    private var lastActivity = Date()
    private var idleCheckPending = false

    /// The composition root: the app passes `openDefaultCore`,
    /// `defaultPreferencesFile` and the system browser, tests a core over a
    /// temporary database, in-memory ports, a temporary preferences file and
    /// a recorder.
    init(
        opening open: () throws -> (core: CoreFacade, keystore: DeviceKeystore),
        preferences file: () throws -> PreferencesFile,
        systemLanguage: String,
        browser: BrowserAuthorization
    ) {
        self.systemLanguage = systemLanguage
        self.browser = browser
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
        startupTouchIDPending = unlockAttemptRememberedAtStartup(startup: true, armed: armed, phase: .unlock) && screen == .master(.unlock)
        keystore?.setPromptReason(strings("unlock.touchIdReason"))
        if let rememberedError {
            error = message(for: rememberedError)
        }
    }

    /// What Touch ID can do on this device right now; never prompts.
    var keystoreStatus: PlatformKeystoreStatus? {
        keystore?.status()
    }

    /// The unlock view calls this when active. Consume the attempt before
    /// prompting: the system sheet can deactivate and reactivate the scene.
    func unlockWithTouchIDAtStartup() async {
        guard startupTouchIDPending, screen == .master(.unlock), !busy else { return }
        startupTouchIDPending = false
        guard keystoreStatus?.biometricsAvailable == true else { return }
        await unlockWithTouchID()
    }

    /// Prompts for Touch ID; dismissing the prompt leaves no error behind.
    func unlockWithTouchID() async {
        guard let core, !busy, touchIDArmed else { return }
        startupTouchIDPending = false
        platformUnlockPending = true
        defer { platformUnlockPending = false }
        let needsEnrollment = syncAfterUnlock
        let selected = pendingStorage
        let result = await perform { () -> VaultModel.Contents? in
            _ = try core.unlockRemembered()
            if let selected { try core.setCurrentStorage(id: selected) }
            if needsEnrollment {
                if try !core.activateConnectedAccount() { return nil }
            }
            if core.currentStorageId() == nil {
                guard try core.setupAccounts().contains(where: { $0.enrolled }) else { return nil }
            }
            return try VaultModel.load(core)
        }
        if let result {
            if let contents = result { open(core: core, contents: contents) }
            else { applyUnlockRoute(unlockRouteAfterDevice(enrolled: false, connectedHasKeys: connectedAccountHasKeys), contents: nil) }
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
        let result = await BlockingCore.run {
            Result {
                if enabled {
                    try core.rememberWithKeystore()
                } else {
                    try core.forgetRemembered()
                }
                return try Self.touchIDArmed(core)
            }
        }
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
        deviceUnlocked
    }

    /// `serverURL` prefills the address, as after forgetting a server.
    func startConnecting(serverURL: String? = nil, storageID: String? = nil, returnTo: Screen = .welcome) {
        guard let core else { return }
        error = nil
        let session: RemoteSession
        do {
            session = try core.remoteSession()
        } catch {
            self.error = message(for: error)
            return
        }
        // Pending tasks retain the previous adapter; do not rely on deinit.
        connect?.cancel()
        connect = ConnectModel(
            session: session, strings: strings, reconnectStorage: storageID, browser: browser,
            copyBrowserUrl: { [weak self] value in
                guard let self else { return }
                Clipboard.copy(value, clearAfter: self.preferences.clipboardClearSeconds,
                               onlyIfUnchanged: self.preferences.clipboardClearIfUnchanged)
            },
            connected: { [weak self] outcome in Task { await self?.connected(outcome) } }
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
        await reconnect(storageID: storageID) { try core.forgetServer(storageId: storageID) }
    }

    /// Connects again to the server of a vault whose connection is gone;
    /// connecting with the same account takes the vault and its unsent
    /// changes over. Like forgetting a server, it locks the vault first.
    func reconnectServer() async {
        guard let gone = vault?.disconnected, !busy else { return }
        let serverURL = gone.serverURL
        await reconnect(storageID: gone.storageID) { serverURL }
    }

    /// Locks the vault, since connecting ends at the master password, and
    /// opens the connect screen at the address `address` returns.
    private func reconnect(storageID: String, _ address: @escaping () throws -> String?) async {
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
        startConnecting(serverURL: serverURL, storageID: storageID, returnTo: .master(.unlock))
    }

    /// Shared routing distinguishes an unlocked device from one needing a password.
    func connected(_ outcome: ConnectModel.Connected) async {
        guard screen == .connect, let core else { return }
        if busy { pendingConnection = outcome; return }
        connect = nil
        syncAfterUnlock = true
        connectedAccountHasKeys = outcome.hasPersonalKeys
        let prepared = await perform { () -> (UnlockRouteFfi, VaultModel.Contents?, SetupAccountFfi?) in
            let status = try core.appStatus()
            let enrolled = status.initialized && !status.locked ? try core.activateConnectedAccount() : false
            let route = unlockRouteAfterConnection(initialized: status.initialized, unlocked: !status.locked, enrolled: enrolled, hasKeys: outcome.hasPersonalKeys)
            let account = try core.setupAccounts().first { $0.storageId == outcome.storageID }
            if case .open = route { return (route, try VaultModel.load(core), account) }
            return (route, nil, account)
        }
        guard let (route, contents, account) = prepared else { showAccountRecovery(); return }
        enrollmentAccount = account
        applyUnlockRoute(route, contents: contents)
    }

    func showAccountRecovery() {
        guard let core, !busy else { return }
        connect?.cancel(); connect = nil
        vault?.stopAutoSync(); vault = nil
        syncAfterUnlock = false; connectedAccountHasKeys = nil; pendingStorage = nil
        recovery = RecoveryModel(core: core, strings: strings, stateChanged: { [weak self] in self?.refreshUnlockState() }) { [weak self] result in
            if result.deviceReset { self?.touchIDArmed = false; self?.startupTouchIDPending = false }
        }
        screen = .accounts
    }

    func chooseSetupAccount(_ account: SetupAccountFfi) async {
        guard let core, !busy else { return }
        let prepared = await perform { () -> (UnlockRouteFfi, VaultModel.Contents?) in
            let status = try core.appStatus()
            let route = unlockRouteForAccount(enrolled: account.enrolled, unlocked: !status.locked)
            if case .open = route { try core.setCurrentStorage(id: account.storageId); return (route, try VaultModel.load(core)) }
            return (route, nil)
        }
        guard let (route, contents) = prepared else { return }
        if case .connect = route { startConnecting(serverURL: account.serverUrl, storageID: account.storageId, returnTo: .accounts) }
        else { pendingStorage = account.storageId; applyUnlockRoute(route, contents: contents) }
    }

    private func applyUnlockRoute(_ route: UnlockRouteFfi, contents: VaultModel.Contents?) {
        switch route {
        case .password(let phase): screen = .master(phase)
        case .chooseAccount: showAccountRecovery()
        case .connect: showAccountRecovery()
        case .open:
            if let core, let contents { pendingStorage = nil; open(core: core, contents: contents) }
        }
    }

    func submit(password: String, mode: MasterMode) async {
        guard let core, !busy, !password.isEmpty else { return }
        startupTouchIDPending = false
        let needsEnrollment = syncAfterUnlock
        let selected = pendingStorage
        let result = await perform { () -> VaultModel.Contents? in
            switch mode {
            case .create: _ = try core.initializeMasterPassword(password: password)
            case .unlock: _ = try core.unlock(password: password)
            case .accountCreate, .accountUnlock: _ = try core.enrollAccountKey(password: password)
            }
            if let selected { try core.setCurrentStorage(id: selected) }
            if needsEnrollment && (mode == .create || mode == .unlock) {
                if try !core.activateConnectedAccount() { return nil }
            }
            if core.currentStorageId() == nil {
                guard try core.setupAccounts().contains(where: { $0.enrolled }) else { return nil }
            }
            return try VaultModel.load(core)
        }
        guard let result else { return }
        if let contents = result {
            open(core: core, contents: contents)
        } else {
            applyUnlockRoute(unlockRouteAfterDevice(enrolled: false, connectedHasKeys: connectedAccountHasKeys), contents: nil)
        }
    }

    /// Open cached content immediately; even the first server sync runs behind
    /// the usable vault UI. The core still owns preferred-storage selection.
    private func open(core: CoreFacade, contents: VaultModel.Contents) {
        let vault = VaultModel(core: core, contents: contents, strings: strings)
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
        guard !idleCheckPending, unlockIdleLockDue(unlocked: isUnlocked, timeoutMinutes: minutes, idleMillis: Int64(now.timeIntervalSince(lastActivity) * 1000)), let core else { return }
        idleCheckPending = true
        defer { idleCheckPending = false }
        do {
            let present = try await BlockingCore.run { Result { try core.idleUnlockKeyPresent() } }.get()
            guard unlockIdleLockDue(unlocked: isUnlocked, timeoutMinutes: minutes, idleMillis: Int64(now.timeIntervalSince(lastActivity) * 1000)) else { return }
            if present { lastActivity = now } else { await lock() }
        } catch {
            await lock()
            self.error = message(for: error)
        }
    }

    func appResignedActive() async {
        if preferences.lockOnFocusLoss && unlockFocusLockRequired(unlocked: isUnlocked, workPending: busy, platformPrompt: platformUnlockPending || touchIDBusy) {
            await lock()
        }
    }

    /// The app was hidden, or its window minimized or closed.
    func appHidden() async {
        if preferences.lockOnHidden {
            await lock()
        }
    }

    /// Called after the OS adapter has synchronously covered the window.
    /// Drain canceled work before the final lock, so late biometric/KDF results
    /// cannot leave keys live after background cleanup completes.
    func secureForBackground() -> Task<Void, Never> {
        let pending = pendingCoreWork
        let shouldLock = preferences.lockOnHidden || !isUnlocked || busy || touchIDBusy
        unlockOperations.cancel()
        pendingConnection = nil
        startupTouchIDPending = false
        connect?.cancel()
        keystore?.cancelUnlock()
        logoutOperation?.cancel()
        vault?.stopAutoSync()
        if preferences.clipboardClearOnExit { Clipboard.clearOwned() }
        guard let core, shouldLock else { return Task {} }
        vault = nil
        deviceUnlocked = false
        if case .vault = screen { screen = .master(.unlock) }
        if preferences.clipboardClearOnLock { Clipboard.clearOwned() }
        return Task {
            await pending?.value
            if let status = await closeCore(core), case .master = screen {
                showLockedDevice(status)
            }
            pendingCoreWork = nil
            busy = false
        }
    }

    func resumeFromBackground() async {
        await checkIdle()
        if isUnlocked { vault?.startAutoSync() }
        guard let core, !busy, !touchIDBusy else { return }
        let status = await BlockingCore.run { Result { try Self.touchIDArmed(core) } }
        switch status {
        case .success(let armed): touchIDArmed = armed
        case .failure(let failure): lastFailure = failure; error = message(for: failure)
        }
    }

    /// Locks locally before the canonical, credential-aware logout. An
    /// offline replica remains available through its normal unlock screen.
    func logout() async {
        guard let core, isUnlocked, !busy else { return }
        // Before the first catalog arrives there is no local storage ID.
        // The session owner resolves that client's active connection itself.
        let storageID = vault?.storageID
        let operation: SessionOperationFfi
        do { operation = try SessionOperationFfi(timeoutMs: 30_000) }
        catch { lastFailure = error; self.error = message(for: error); return }
        logoutOperation = operation
        defer { logoutOperation = nil }
        vault?.stopAutoSync()
        vault = nil
        screen = .master(.unlock)
        if preferences.clipboardClearOnLock { Clipboard.clearOwned() }
        _ = await perform {
            _ = try core.lock()
            return try core.remoteSession().logout(storageId: storageID, operation: operation)
        }
    }

    private func closeCore(_ core: CoreFacade) async -> AppStatusFfi? {
        let result = await BlockingCore.run {
            Result { _ = try core.lock(); return try core.appStatus() }
        }
        switch result {
        case .success(let status): return status
        case .failure(let failure):
            lastFailure = failure
            screen = .failed(message(for: failure))
            return nil
        }
    }

    private func showLockedDevice(_ status: AppStatusFfi) {
        screen = .master(status.initialized ? .unlock : .create)
    }

    func lock() async {
        guard let core, isUnlocked || busy else { return }
        let keepConnecting = screen == .connect && connect != nil
        unlockOperations.cancel()
        // Clear visible secrets before awaiting any fallible core operation.
        vault?.stopAutoSync()
        if !keepConnecting { vault = nil; screen = .master(.unlock) }
        // The core cancels work already running.
        guard let status = await perform({ _ = try core.lock(); return try core.appStatus() }) else { return }
        vault = nil
        if preferences.clipboardClearOnLock {
            Clipboard.clearOwned()
        }
        if keepConnecting {
            if let outcome = pendingConnection { pendingConnection = nil; await connected(outcome) }
        } else { showLockedDevice(status) }
    }

    private func refreshUnlockState() {
        guard let core else { return }
        do {
            let unlocked = try core.vaultStatus().unlocked
            if unlocked && !deviceUnlocked { lastActivity = Date() }
            deviceUnlocked = unlocked
        }
        catch { self.error = message(for: error) }
    }

    /// The failure behind the last `nil` from `perform`.
    private var lastFailure: Error?

    /// Runs `work` off the main actor; a failure lands in `error` as `nil`.
    private func perform<T>(_ work: @escaping () throws -> T) async -> T? {
        guard let operation = unlockOperations.begin() else { return nil }
        busy = true
        error = nil
        lastFailure = nil
        let pending = Task(priority: .userInitiated) { await BlockingCore.run { Result(catching: work) } }
        pendingCoreWork = Task { _ = await pending.value }
        let result = await pending.value
        guard unlockOperations.finish(operation: operation) else { return nil }
        pendingCoreWork = nil
        busy = false
        refreshUnlockState()
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


}
