import AppKit

@MainActor
enum Clipboard {
    private static let controller = ClipboardController(sink: MacPasteboardSink())
    static func copy(_ value: String, clearAfter seconds: UInt32, onlyIfUnchanged: Bool) {
        controller.copy(value, clearAfter: seconds, onlyIfUnchanged: onlyIfUnchanged)
    }
    static func clearOwned() { controller.clearOwned() }
}

@MainActor
private final class MacPasteboardSink: ClipboardSink {
    var changeCount: Int { NSPasteboard.general.changeCount }
    func write(_ value: String, expiration: Date?) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)
        pasteboard.setString("", forType: .init("org.nspasteboard.ConcealedType"))
        pasteboard.setString("", forType: .init("org.nspasteboard.TransientType"))
    }
    func clear() { NSPasteboard.general.clearContents() }
}
