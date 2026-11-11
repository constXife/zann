import AppKit
import Combine

/// Feeds the macOS events behind the automatic locks into `AppModel`, which
/// decides from `DevicePreferences` whether each one acts: input in the app's
/// windows as activity, a periodic idle check, losing focus, the app being
/// hidden or its window minimized, and quitting (the clipboard clear on exit).
@MainActor
final class LockTriggers {
    /// How often the idle lock is checked, as in COSMIC.
    private static let idleTick: UInt64 = 30_000_000_000

    private var monitor: Any?
    private var observers: [AnyCancellable] = []
    private var idleTask: Task<Void, Never>?

    init(model: AppModel) {
        let activity: NSEvent.EventTypeMask = [
            .keyDown, .leftMouseDown, .rightMouseDown, .otherMouseDown, .scrollWheel, .mouseMoved,
        ]
        monitor = NSEvent.addLocalMonitorForEvents(matching: activity) { [weak model] event in
            model?.noteActivity()
            return event
        }
        let center = NotificationCenter.default
        observers = [
            center.publisher(for: NSApplication.didResignActiveNotification)
                .sink { [weak model] _ in Task { await model?.appResignedActive() } },
            center.publisher(for: NSApplication.didHideNotification)
                .sink { [weak model] _ in Task { await model?.appHidden() } },
            center.publisher(for: NSWindow.didMiniaturizeNotification)
                .sink { [weak model] _ in Task { await model?.appHidden() } },
            // Synchronous: the process exits before a scheduled task would run.
            center.publisher(for: NSApplication.willTerminateNotification)
                .sink { [weak model] _ in model?.appWillTerminate() },
        ]
        idleTask = Task { [weak model] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: Self.idleTick)
                await model?.checkIdle()
            }
        }
    }

    deinit {
        idleTask?.cancel()
        if let monitor {
            NSEvent.removeMonitor(monitor)
        }
    }
}
