import UIKit

/// Observes activity without competing with UIKit navigation/search gestures.
/// Rejecting each touch in the delegate keeps this recognizer out of delivery.
@MainActor
final class MobileUserActivity: NSObject, UIGestureRecognizerDelegate {
    private let noteActivity: () -> Void
    private let observer = UITapGestureRecognizer()

    init(noteActivity: @escaping () -> Void) {
        self.noteActivity = noteActivity
        super.init()
        observer.delegate = self
        observer.cancelsTouchesInView = false
        observer.delaysTouchesBegan = false
        observer.delaysTouchesEnded = false
    }

    func attach(to window: UIWindow) {
        guard observer.view !== window else { return }
        observer.view?.removeGestureRecognizer(observer)
        window.addGestureRecognizer(observer)
    }

    func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer, shouldReceive touch: UITouch) -> Bool {
        noteActivity()
        return false
    }
}
