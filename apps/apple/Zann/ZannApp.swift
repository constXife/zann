import SwiftUI
import ZannCoreKit

@main
struct ZannApp: App {
    @StateObject private var model = AppModel(
        opening: AppModel.openDefaultCore,
        preferences: AppModel.defaultPreferencesFile,
        systemLanguage: Locale.preferredLanguages.first ?? Locale.current.identifier,
        openBrowser: { NSWorkspace.shared.open($0) }
    )

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .frame(minWidth: 520, minHeight: 380)
        }
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
                Button("Lock") { Task { await model.lock() } }
                    .keyboardShortcut("l", modifiers: .command)
                    .disabled(!model.isUnlocked)
            }
        }
        Settings {
            SettingsView().environmentObject(model)
        }
    }
}

struct RootView: View {
    @EnvironmentObject private var model: AppModel
    @State private var lockTriggers: LockTriggers?

    var body: some View {
        screen
            .onAppear { lockTriggers = lockTriggers ?? LockTriggers(model: model) }
            // Closing the window keeps the app running, so it counts as hidden.
            .onDisappear { Task { await model.appHidden() } }
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
