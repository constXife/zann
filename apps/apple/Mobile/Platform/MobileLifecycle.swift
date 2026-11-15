import UIKit
import Combine

/// The native cover is installed synchronously, before app-switcher snapshots.
/// Background execution is bounded by the OS; process death drops in-memory
/// keys and Rust's auth journals retain their normal recovery semantics.
@MainActor
final class MobileLifecycle: ObservableObject {
    @Published private(set) var visibilityEpoch = 0
    private let model: AppModel
    private let webAuthentication: WebAuthentication
    private let activity: MobileUserActivity
    private weak var window: UIWindow?
    private var cover: UIView?
    private var observers: [AnyCancellable] = []
    private var backgroundWork: Task<Void, Never>?
    private var inactiveWork: Task<Void, Never>?
    private var idle: Task<Void, Never>?

    init(model: AppModel, webAuthentication: WebAuthentication) {
        self.model = model
        self.webAuthentication = webAuthentication
        self.activity = MobileUserActivity { [weak model] in model?.noteActivity() }
        let notifications = NotificationCenter.default
        observers = [
            notifications.publisher(for: UIApplication.willResignActiveNotification)
                .sink { [weak self] _ in self?.resign() },
            notifications.publisher(for: UIApplication.didEnterBackgroundNotification)
                .sink { [weak self] _ in self?.suspend() },
            notifications.publisher(for: UIApplication.protectedDataWillBecomeUnavailableNotification)
                .sink { [weak self] _ in self?.suspend() },
            notifications.publisher(for: UIApplication.protectedDataDidBecomeAvailableNotification)
                .sink { [weak self] _ in self?.resume() },
            notifications.publisher(for: UIApplication.didBecomeActiveNotification)
                .sink { [weak self] _ in self?.resume() },
            notifications.publisher(for: UITextField.textDidChangeNotification)
                .sink { [weak model] _ in model?.noteActivity() },
            notifications.publisher(for: UITextView.textDidChangeNotification)
                .sink { [weak model] _ in model?.noteActivity() },
        ]
    }

    func attach(_ window: UIWindow) {
        self.window = window
        webAuthentication.window = window
        activity.attach(to: window)
        installCover()
        if UIApplication.shared.applicationState == .active { resume() }
    }

    private func installCover() {
        guard cover == nil, let window else { return }
        let cover = UIView(frame: window.bounds)
        cover.backgroundColor = .systemBackground
        cover.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        cover.isAccessibilityElement = true
        cover.accessibilityLabel = "Zann"
        cover.accessibilityViewIsModal = true
        window.addSubview(cover)
        self.cover = cover
    }

    private func resign() {
        installCover()
        visibilityEpoch += 1 // Discards reveal state and local password fields.
        idle?.cancel()
        inactiveWork = Task { await model.appResignedActive() }
    }

    private func suspend() {
        resign()
        webAuthentication.cancel()
        guard backgroundWork == nil else { return }
        let lease = BackgroundExecutionLease()
        let locking = model.secureForBackground()
        backgroundWork = Task {
            await locking.value
            lease.end()
        }
    }

    private func resume() {
        let epoch = visibilityEpoch
        Task { [weak self] in
            guard let self else { return }
            await inactiveWork?.value
            await backgroundWork?.value
            guard epoch == visibilityEpoch, UIApplication.shared.applicationState == .active,
                  UIApplication.shared.isProtectedDataAvailable else { return }
            backgroundWork = nil
            Clipboard.reconcile()
            await model.resumeFromBackground()
            guard epoch == visibilityEpoch, UIApplication.shared.applicationState == .active else { return }
            cover?.removeFromSuperview()
            cover = nil
            idle?.cancel()
            idle = Task { [weak model = self.model] in
                while !Task.isCancelled {
                    try? await Task.sleep(nanoseconds: 30_000_000_000)
                    guard !Task.isCancelled else { return }
                    await model?.checkIdle()
                }
            }
        }
    }
}

@MainActor
private final class BackgroundExecutionLease {
    private var identifier: UIBackgroundTaskIdentifier = .invalid
    init() {
        identifier = UIApplication.shared.beginBackgroundTask { [weak self] in
            Task { @MainActor in self?.end() }
        }
    }
    func end() {
        let owned = identifier
        identifier = .invalid
        if owned != .invalid { UIApplication.shared.endBackgroundTask(owned) }
    }
}
