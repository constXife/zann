import SwiftUI
import UIKit

struct WindowAttachment: UIViewRepresentable {
    let attached: (UIWindow) -> Void
    func makeUIView(context: Context) -> AttachmentView { AttachmentView(attached: attached) }
    func updateUIView(_ view: AttachmentView, context: Context) {}

    final class AttachmentView: UIView {
        private let attached: (UIWindow) -> Void
        init(attached: @escaping (UIWindow) -> Void) {
            self.attached = attached
            super.init(frame: .zero)
        }
        required init?(coder: NSCoder) { nil }
        override func didMoveToWindow() {
            super.didMoveToWindow()
            if let window { attached(window) }
        }
    }
}
