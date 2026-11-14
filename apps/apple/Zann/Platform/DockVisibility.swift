import AppKit
import Combine

/// Dock presence is a macOS UI preference, separate from portable vault
/// policies. Window visibility comes from AppKit, including Settings and
/// minimized windows; no second window registry is maintained.
@MainActor
final class DockVisibility: ObservableObject {
    static let preferenceKey = "apple.hideDockWhenWindowsClosed"

    @Published var hideWhenClosed: Bool {
        didSet {
            guard hideWhenClosed != oldValue else { return }
            defaults.set(hideWhenClosed, forKey: Self.preferenceKey)
            refresh()
        }
    }

    private let defaults: UserDefaults
    private let hasOpenWindows: @MainActor (NSWindow?) -> Bool
    private let applyPolicy: @MainActor (NSApplication.ActivationPolicy) -> Void
    private var observers: [AnyCancellable] = []

    init(
        defaults: UserDefaults = .standard,
        notifications: NotificationCenter = .default,
        hasOpenWindows: @escaping @MainActor (NSWindow?) -> Bool = { closing in
            NSApp.windows.contains { window in
                window !== closing && window.styleMask.contains(.titled)
                    && (window.isVisible || window.isMiniaturized)
            }
        },
        applyPolicy: @escaping @MainActor (NSApplication.ActivationPolicy) -> Void = { policy in
            if NSApp.activationPolicy() != policy {
                NSApp.setActivationPolicy(policy)
            }
        }
    ) {
        self.defaults = defaults
        self.hasOpenWindows = hasOpenWindows
        self.applyPolicy = applyPolicy
        defaults.register(defaults: [Self.preferenceKey: true])
        hideWhenClosed = defaults.bool(forKey: Self.preferenceKey)
        observers = [
            notifications.publisher(for: NSWindow.willCloseNotification)
                .sink { [weak self] notification in
                    guard let window = notification.object as? NSWindow,
                          window.styleMask.contains(.titled) else { return }
                    self?.refresh(excluding: window)
                },
            notifications.publisher(for: NSWindow.didBecomeMainNotification)
                .sink { [weak self] _ in self?.showForWindow() },
        ]
    }

    /// Restore normal activation before reopening from the menu bar, so the
    /// window receives focus and the app's commands return with its Dock icon.
    func showForWindow() {
        applyPolicy(.regular)
    }

    private func refresh(excluding closing: NSWindow? = nil) {
        applyPolicy(hideWhenClosed && !hasOpenWindows(closing) ? .accessory : .regular)
    }
}
