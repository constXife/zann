import AppKit
import XCTest
@testable import Zann

@MainActor
final class MenuBarControllerTests: XCTestCase {
    private func model() -> AppModel {
        AppModel(opening: { throw CocoaError(.fileNoSuchFile) }, preferences: {
            PreferencesFile(url: FileManager.default.temporaryDirectory
                .appendingPathComponent("zann-menu-\(UUID().uuidString).json"))
        }, systemLanguage: "en", openBrowser: { _ in })
    }

    private func click(_ type: NSEvent.EventType, modifiers: NSEvent.ModifierFlags = []) throws -> NSEvent {
        try XCTUnwrap(NSEvent.mouseEvent(
            with: type, location: .zero, modifierFlags: modifiers, timestamp: 0,
            windowNumber: 0, context: nil, eventNumber: 0, clickCount: 1, pressure: 0
        ))
    }

    func testLeftClickAndAccessibilityPressOpenWithoutAMenu() throws {
        var opened = 0
        var menus = 0
        let controller = MenuBarController(model: model(), openWindow: { opened += 1 },
                                           presentMenu: { _, _ in menus += 1 })
        controller.handleClick(event: try click(.leftMouseUp))
        controller.handleClick(event: nil)
        XCTAssertEqual(opened, 2)
        XCTAssertEqual(menus, 0)
    }

    func testRightClickShowsMenuAndItsOpenActionUsesTheSameWindow() throws {
        var opened = 0
        var menu: NSMenu?
        let controller = MenuBarController(model: model(), openWindow: { opened += 1 },
                                           presentMenu: { shown, _ in menu = shown })
        controller.handleClick(event: try click(.rightMouseUp))
        XCTAssertEqual(opened, 0)
        let shown = try XCTUnwrap(menu)
        XCTAssertEqual(shown.items.map(\.title), ["Open", "", "Lock", "", "Quit"])
        XCTAssertFalse(shown.items[2].isEnabled, "a locked app cannot lock again")
        shown.performActionForItem(at: 0)
        XCTAssertEqual(opened, 1)
    }

    func testControlClickUsesTheContextMenu() throws {
        var opened = 0
        var menus = 0
        let controller = MenuBarController(model: model(), openWindow: { opened += 1 },
                                           presentMenu: { _, _ in menus += 1 })
        controller.handleClick(event: try click(.leftMouseUp, modifiers: .control))
        XCTAssertEqual(opened, 0)
        XCTAssertEqual(menus, 1)
    }
}
