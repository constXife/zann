import AppKit
import SwiftUI

/// NSSearchField consumes arrow keys before SwiftUI's list can see them.
/// Route Down/Return from this window's search to its results, leaving text
/// editing, input-method composition, sheets and other windows untouched.
struct SearchResultNavigation: NSViewRepresentable {
    let selectFirst: () -> Bool

    func makeNSView(context: Context) -> MonitorView {
        MonitorView(selectFirst: selectFirst)
    }

    func updateNSView(_ view: MonitorView, context: Context) {
        view.selectFirst = selectFirst
    }

    final class MonitorView: NSView {
        var selectFirst: () -> Bool
        private var monitor: Any?

        init(selectFirst: @escaping () -> Bool) {
            self.selectFirst = selectFirst
            super.init(frame: .zero)
            monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
                guard let self, self.shouldRoute(event), self.selectFirst() else { return event }
                return nil
            }
        }

        required init?(coder: NSCoder) { nil }

        deinit {
            if let monitor { NSEvent.removeMonitor(monitor) }
        }

        private func shouldRoute(_ event: NSEvent) -> Bool {
            guard [UInt16(125), 36, 76].contains(event.keyCode),
                  event.modifierFlags.intersection([.command, .control, .option, .shift]).isEmpty,
                  let window, event.window === window, window.attachedSheet == nil,
                  let editor = window.firstResponder as? NSTextView,
                  !editor.hasMarkedText(), editor.delegate is NSSearchField else { return false }
            return true
        }
    }
}
