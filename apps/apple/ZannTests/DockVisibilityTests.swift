import AppKit
import XCTest
@testable import Zann

@MainActor
final class DockVisibilityTests: XCTestCase {
    private var suite: String!
    private var defaults: UserDefaults!
    private var notifications: NotificationCenter!

    override func setUpWithError() throws {
        suite = "zann-dock-tests-\(UUID().uuidString)"
        defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        notifications = NotificationCenter()
    }

    override func tearDownWithError() throws {
        defaults.removePersistentDomain(forName: suite)
    }

    private func window() -> NSWindow {
        NSWindow(contentRect: .zero, styleMask: [.titled, .closable],
                 backing: .buffered, defer: true)
    }

    func testHidesByDefaultAndPersistsAnExplicitOptOut() {
        var policies: [NSApplication.ActivationPolicy] = []
        let dock = DockVisibility(defaults: defaults, notifications: notifications,
                                  hasOpenWindows: { _ in false },
                                  applyPolicy: { policies.append($0) })
        XCTAssertTrue(dock.hideWhenClosed)
        XCTAssertTrue(policies.isEmpty, "launch keeps normal activation until a window closes")

        dock.hideWhenClosed = false
        XCTAssertEqual(policies.last, .regular)
        let reopened = DockVisibility(defaults: defaults, notifications: notifications,
                                      hasOpenWindows: { _ in false }, applyPolicy: { _ in })
        XCTAssertFalse(reopened.hideWhenClosed)
    }

    func testClosingLastWindowHidesDockAndOpeningRestoresIt() {
        let closing = window()
        var policies: [NSApplication.ActivationPolicy] = []
        let dock = DockVisibility(defaults: defaults, notifications: notifications,
                                  hasOpenWindows: { excluded in
                                      XCTAssertTrue(excluded === closing)
                                      return false
                                  }, applyPolicy: { policies.append($0) })

        notifications.post(name: NSWindow.willCloseNotification, object: closing)
        XCTAssertEqual(policies.last, .accessory)
        dock.showForWindow()
        XCTAssertEqual(policies.last, .regular)
    }

    func testAnotherOpenWindowKeepsDockVisible() {
        var policies: [NSApplication.ActivationPolicy] = []
        let dock = DockVisibility(defaults: defaults, notifications: notifications,
                                  hasOpenWindows: { _ in true },
                                  applyPolicy: { policies.append($0) })
        notifications.post(name: NSWindow.willCloseNotification, object: window())
        XCTAssertEqual(policies.last, .regular)
        withExtendedLifetime(dock) {}
    }

    func testClosingWithSettingOffKeepsDockVisible() {
        defaults.set(false, forKey: DockVisibility.preferenceKey)
        var policies: [NSApplication.ActivationPolicy] = []
        let dock = DockVisibility(defaults: defaults, notifications: notifications,
                                  hasOpenWindows: { _ in false },
                                  applyPolicy: { policies.append($0) })
        notifications.post(name: NSWindow.willCloseNotification, object: window())
        XCTAssertEqual(policies.last, .regular)
        withExtendedLifetime(dock) {}
    }

    func testReactivatedWindowRestoresDockPresence() {
        var policies: [NSApplication.ActivationPolicy] = []
        let dock = DockVisibility(defaults: defaults, notifications: notifications,
                                  hasOpenWindows: { _ in false },
                                  applyPolicy: { policies.append($0) })
        notifications.post(name: NSWindow.willCloseNotification, object: window())
        XCTAssertEqual(policies.last, .accessory)
        notifications.post(name: NSWindow.didBecomeMainNotification, object: window())
        XCTAssertEqual(policies.last, .regular)
        withExtendedLifetime(dock) {}
    }
}
