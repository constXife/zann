import SwiftUI
import ZannCoreKit

/// Xcode runs the unit tests inside this app. While it hosts them it opens
/// no vault: the tests bring their own cores over temporary databases, and
/// the user's vault, Keychain items and sync stay out of the test process.
@main
enum ZannMain {
    static func main() {
        if ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil {
            TestHostApp.main()
        } else {
            ZannApp.main()
        }
    }
}

private struct TestHostApp: App {
    var body: some Scene {
        Settings { EmptyView() }
    }
}

struct ZannApp: App {
    @StateObject private var model = AppModel(
        opening: AppModel.openDefaultCore,
        preferences: AppModel.defaultPreferencesFile,
        systemLanguage: Locale.preferredLanguages.first ?? Locale.current.identifier,
        openBrowser: { NSWorkspace.shared.open($0) }
    )
    // Security observers must outlive a closed vault window while the app
    // remains in the menu bar (idle lock and clear-on-exit included).
    @State private var lockTriggers: LockTriggers?

    var body: some Scene {
        Window("Zann", id: mainWindowID) {
            RootView()
                .environmentObject(model)
                .onAppear {
                    if lockTriggers == nil { lockTriggers = LockTriggers(model: model) }
                }
        }
        // Room for all three vault columns from the first launch; the window
        // also grows to the vault's own minimum when it opens.
        .defaultSize(width: 1180, height: 760)
        .windowResizability(.contentMinSize)
        .commands {
            // One vault window: ⌘N creates an item rather than a second window.
            CommandGroup(replacing: .newItem) {
                Button(model.strings("common.create")) { model.vault?.startCreating() }
                    .keyboardShortcut("n", modifiers: .command)
                    .disabled(model.vault == nil)
            }
            CommandGroup(after: .pasteboard) {
                Button(model.strings("common.edit")) {
                    Task { await model.vault?.startEditing() }
                }
                .keyboardShortcut("e", modifiers: .command)
                .disabled(model.vault == nil)
            }
            CommandMenu("Vault") {
                Button(model.strings("settings.accounts.syncNow")) {
                    Task { await model.vault?.sync() }
                }
                .keyboardShortcut("r", modifiers: .command)
                // Commands observe only AppModel; a vault with no server
                // makes this a no-op.
                .disabled(model.vault == nil)
                Button(model.strings("common.lock")) { Task { await model.lock() } }
                    .keyboardShortcut("l", modifiers: .command)
                    .disabled(!model.isUnlocked)
            }
        }
        MenuBarExtra("Zann", systemImage: "key.fill") {
            MenuBarControls().environmentObject(model)
        }
        .menuBarExtraStyle(.menu)
        Settings {
            SettingsView().environmentObject(model)
        }
    }
}

struct RootView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        screen
            // The one place the window minimum is set: an outer minimum would
            // hide the vault's larger one from the window.
            .frame(minWidth: minimum.width, minHeight: minimum.height)
            // Closing the window keeps the app running, so it counts as hidden.
            .onDisappear { Task { await model.appHidden() } }
    }

    /// Three vault columns need more room than the single-column screens.
    private var minimum: CGSize {
        model.screen == .vault ? CGSize(width: 900, height: 560) : CGSize(width: 520, height: 380)
    }

    @ViewBuilder private var screen: some View {
        switch model.screen {
        case .failed(let message):
            ContentUnavailableNotice(title: "Zann could not open its database", message: message)
        case .welcome:
            WelcomeView()
        case .connect:
            if let connect = model.connect {
                ConnectView(connect: connect)
            }
        case .master(let mode):
            MasterPasswordView(mode: mode)
        case .vault:
            if let vault = model.vault {
                VaultView(vault: vault)
            }
        }
    }
}

/// `ContentUnavailableView` needs macOS 14; the app targets 13.
struct ContentUnavailableNotice: View {
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: 8) {
            Text(title).font(.title2)
            Text(message).foregroundStyle(.secondary).textSelection(.enabled)
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
