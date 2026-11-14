import AppKit

/// A native status item survives its windows. Closing the last SwiftUI
/// window must therefore leave the app running; Quit remains explicit.
@MainActor
final class ApplicationLifecycle: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}
