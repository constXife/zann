import SwiftUI

/// One window, shared by the Dock and the menu bar. Opening it again raises
/// the existing window instead of creating a second unlocked workspace.
let mainWindowID = "main"

/// App-owned so closing the window does not remove the status item. Keep its
/// menu detached: a permanently attached NSMenu consumes left clicks too.
@MainActor
final class MenuBarController: NSObject {
    private let statusItem: NSStatusItem
    private let model: AppModel
    private let openWindow: @MainActor () -> Void
    private let presentMenu: @MainActor (NSMenu, NSStatusBarButton) -> Void

    init(
        model: AppModel,
        openWindow: @escaping @MainActor () -> Void,
        presentMenu: @escaping @MainActor (NSMenu, NSStatusBarButton) -> Void = { menu, button in
            _ = menu.popUp(positioning: nil, at: NSPoint(x: 0, y: button.bounds.minY), in: button)
        }
    ) {
        self.model = model
        self.openWindow = openWindow
        self.presentMenu = presentMenu
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        super.init()
        statusItem.autosaveName = "ZannMenuBar"
        guard let button = statusItem.button else {
            preconditionFailure("NSStatusItem did not create its button")
        }
        button.image = NSImage(systemSymbolName: "key.fill", accessibilityDescription: "Zann")
        button.image?.isTemplate = true
        button.setAccessibilityLabel("Zann")
        button.target = self
        button.action = #selector(clicked)
        button.sendAction(on: [.leftMouseUp, .rightMouseUp])
    }

    @objc private func clicked() {
        handleClick(event: NSApp.currentEvent)
    }

    /// A keyboard or accessibility press has the same primary action as a
    /// left click; right click and macOS's Ctrl-click open the context menu.
    func handleClick(event: NSEvent?) {
        if event?.type == .rightMouseUp || event?.modifierFlags.contains(.control) == true {
            guard let button = statusItem.button else {
                preconditionFailure("NSStatusItem lost its button")
            }
            presentMenu(makeMenu(), button)
        } else {
            openWindow()
        }
    }

    private func makeMenu() -> NSMenu {
        let menu = NSMenu()
        menu.autoenablesItems = false
        let openItem = menu.addItem(withTitle: model.strings("common.open"),
                                action: #selector(open), keyEquivalent: "")
        openItem.target = self
        menu.addItem(.separator())
        let lockItem = menu.addItem(withTitle: model.strings("common.lock"),
                                action: #selector(lock), keyEquivalent: "")
        lockItem.target = self
        lockItem.isEnabled = model.isUnlocked && !model.busy
        menu.addItem(.separator())
        let quitItem = menu.addItem(withTitle: model.strings("common.quit"),
                                action: #selector(quit), keyEquivalent: "q")
        quitItem.target = self
        return menu
    }

    @objc private func open() { openWindow() }
    @objc private func lock() { Task { await model.lock() } }
    @objc private func quit() { NSApp.terminate(nil) }
}

/// Captures SwiftUI's single-window action once. The app retains the native
/// controller after this view disappears with its closed window.
struct MenuBarInstaller: View {
    @Binding var controller: MenuBarController?
    let model: AppModel
    let dock: DockVisibility
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Color.clear.frame(width: 0, height: 0).onAppear {
            guard controller == nil else { return }
            let dock = dock
            let openWindow = openWindow
            controller = MenuBarController(model: model, openWindow: {
                dock.showForWindow()
                openWindow(id: mainWindowID)
                NSApp.activate(ignoringOtherApps: true)
            })
        }
    }
}
