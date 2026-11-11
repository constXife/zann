import AppKit
import Combine

/// Whether the reveal modifier (Option on macOS) is held while the app is
/// active. Holding it reveals masked values only for as long as it is held;
/// deactivating the app drops it, per docs/ux/Layout-Responsive-Spec.md.
@MainActor
final class RevealModifier: ObservableObject {
    @Published private(set) var isHeld = false

    private var monitor: Any?
    private var resign: AnyCancellable?

    init() {
        monitor = NSEvent.addLocalMonitorForEvents(matching: .flagsChanged) { [weak self] event in
            self?.isHeld = event.modifierFlags.contains(.option)
            return event
        }
        resign = NotificationCenter.default
            .publisher(for: NSApplication.didResignActiveNotification)
            .sink { [weak self] _ in self?.isHeld = false }
    }

    deinit {
        if let monitor {
            NSEvent.removeMonitor(monitor)
        }
    }
}
