import SwiftUI

@main
struct ZannApp: App {
    @StateObject private var model = AppModel(
        opening: AppModel.openDefaultCore,
        language: Locale.preferredLanguages.first ?? Locale.current.identifier
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
                Button("Lock") { Task { await model.lock() } }
                    .keyboardShortcut("l", modifiers: .command)
                    .disabled(!model.isUnlocked)
            }
        }
    }
}

struct RootView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        switch model.screen {
        case .failed(let message):
            ContentUnavailableNotice(title: "Zann could not open its database", message: message)
        case .welcome:
            WelcomeView()
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
