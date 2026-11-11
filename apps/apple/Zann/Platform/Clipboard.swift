import AppKit

/// Copies secrets to the general pasteboard and clears them on schedule.
/// Values are marked concealed and transient so clipboard managers that honour
/// nspasteboard.org skip them.
@MainActor
enum Clipboard {
    private static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    private static let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
    /// The change count of our last write; nil when the pasteboard is not ours.
    private static var ownedChangeCount: Int?

    static func copy(_ value: String, clearAfter seconds: UInt32, onlyIfUnchanged: Bool) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)
        pasteboard.setString("", forType: concealed)
        pasteboard.setString("", forType: transient)
        let changeCount = pasteboard.changeCount
        ownedChangeCount = changeCount
        guard seconds > 0 else { return }
        Task {
            try? await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000)
            if !onlyIfUnchanged || NSPasteboard.general.changeCount == changeCount {
                clearOwned()
            }
        }
    }

    /// Clears the pasteboard if it still holds the last value copied here.
    static func clearOwned() {
        guard let ownedChangeCount, NSPasteboard.general.changeCount == ownedChangeCount else {
            return
        }
        NSPasteboard.general.clearContents()
        self.ownedChangeCount = nil
    }
}
