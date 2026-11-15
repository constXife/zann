import UIKit
import UniformTypeIdentifiers

@MainActor
enum Clipboard {
    private static let controller = ClipboardController(sink: MobilePasteboardSink(pasteboard: .general))
    static func copy(_ value: String, clearAfter seconds: UInt32, onlyIfUnchanged: Bool) {
        controller.copy(value, clearAfter: seconds, onlyIfUnchanged: onlyIfUnchanged)
    }
    static func clearOwned() { controller.clearOwned() }
    static func reconcile() { controller.reconcile() }
}

@MainActor
final class MobilePasteboardSink: ClipboardSink {
    private let pasteboard: UIPasteboard
    init(pasteboard: UIPasteboard) { self.pasteboard = pasteboard }
    var changeCount: Int { pasteboard.changeCount }
    func write(_ value: String, expiration: Date?) {
        var options: [UIPasteboard.OptionsKey: Any] = [.localOnly: true]
        if let expiration { options[.expirationDate] = expiration }
        pasteboard.setItems([[UTType.utf8PlainText.identifier: value]], options: options)
    }
    func clear() { pasteboard.items = [] }
}
