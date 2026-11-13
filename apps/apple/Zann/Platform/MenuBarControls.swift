import SwiftUI

/// One window, shared by the Dock and the menu bar. Opening it again raises
/// the existing window instead of creating a second unlocked workspace.
let mainWindowID = "main"

struct MenuBarControls: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button(model.strings("common.open")) {
            openWindow(id: mainWindowID)
            NSApp.activate(ignoringOtherApps: true)
        }
        Divider()
        Button(model.strings("common.lock")) {
            Task { await model.lock() }
        }
        .disabled(!model.isUnlocked || model.busy)
        Divider()
        Button(model.strings("common.quit")) { NSApp.terminate(nil) }
            .keyboardShortcut("q", modifiers: .command)
    }
}
