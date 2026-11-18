import XCTest
import UIKit

/// Runs on both device families in CI. Every screenshot uses a temporary,
/// explicitly selected synthetic replica; no real account is necessary.
@MainActor
final class MobileWorkspaceTests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
        XCUIDevice.shared.orientation = .portrait
    }

    func testDetailEditorAndDraftSurviveRotation() throws {
        let app = launchFixture()
        let search = app.searchFields.firstMatch
        search.tap()
        search.typeText("Example account")
        XCTAssertTrue(app.buttons["item.Example account"].waitForExistence(timeout: 5))
        app.buttons["item.Example account"].tap()
        let reveal = app.buttons["detail.reveal.password"]
        XCTAssertTrue(reveal.waitForExistence(timeout: 5))
        XCTAssertGreaterThanOrEqual(reveal.frame.height, 44)
        XCTAssertTrue(app.descendants(matching: .any).matching(NSPredicate(format: "identifier BEGINSWITH %@", "detail.totp.")).firstMatch.exists)
        capture(app, "detail-portrait-masked")
        // The fixture holds copy feedback until a reset, so the accessible
        // value cannot expire before this check on a slow simulator.
        let copied = NSPredicate(format: "value CONTAINS %@", "Copied")
        let copy = app.buttons["detail.copy.password"]
        copy.tap()
        expectation(for: copied, evaluatedWith: copy)
        waitForExpectations(timeout: 5)
        reveal.tap()
        XCTAssertEqual(reveal.label, "Hide")
        XCUIDevice.shared.orientation = .landscapeLeft
        XCTAssertTrue(app.buttons["detail.reveal.password"].waitForExistence(timeout: 5))
        expectation(for: NSPredicate(format: "label == %@", "Reveal"), evaluatedWith: app.buttons["detail.reveal.password"])
        expectation(for: NSCompoundPredicate(notPredicateWithSubpredicate: copied), evaluatedWith: app.buttons["detail.copy.password"])
        waitForExpectations(timeout: 5)
        let storage = app.buttons["workspace.storage"]
        if UIDevice.current.userInterfaceIdiom == .pad && app.windows.firstMatch.frame.width >= 900 {
            XCTAssertTrue(storage.waitForExistence(timeout: 5))
            XCTAssertTrue(storage.label.contains("fixture.example.test"))
            XCTAssertGreaterThanOrEqual(storage.frame.height, 44)
            XCTAssertLessThanOrEqual(storage.frame.height, 64)
        }
        capture(app, "detail-landscape-masked")

        app.buttons["workspace.edit"].tap()
        let name = app.textFields["editor.title"]
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        name.tap()
        name.typeText(" edited")
        let changedTitle = name.value as? String
        XCTAssertTrue(app.keyboards.firstMatch.waitForExistence(timeout: 5))
        capture(app, "editor-keyboard-landscape")
        XCUIDevice.shared.orientation = .portrait
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        XCTAssertEqual(name.value as? String, changedTitle)
        capture(app, "editor-keyboard-portrait-draft")
        app.buttons["editor.save"].tap()
        XCTAssertTrue(app.buttons["workspace.edit"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts[try XCTUnwrap(changedTitle)].firstMatch.waitForExistence(timeout: 5))
        capture(app, "detail-saved")
    }

    func testCreateAndInAppSettingsWithAccessibilityText() throws {
        let app = launchFixture(largeText: true)
        capture(app, "items-accessibility-text")
        app.buttons["workspace.create"].tap()
        app.buttons["create.type.login"].tap()
        let name = app.textFields["editor.title"]
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        XCTAssertGreaterThanOrEqual(app.staticTexts["Name"].firstMatch.frame.height, 44)
        name.tap()
        name.typeText("Created by touch")
        capture(app, "create-accessibility-text-keyboard")
        XCTAssertTrue(app.buttons["editor.save"].isHittable)
        app.buttons["editor.save"].tap()
        XCTAssertTrue(app.buttons["workspace.edit"].waitForExistence(timeout: 5))
        app.buttons["workspace.settings"].tap()
        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 5))
        XCTAssertGreaterThanOrEqual(app.staticTexts["Language"].firstMatch.frame.height, 44)
        capture(app, "settings-accessibility-text")
        try app.performAccessibilityAudit(for: [.elementDetection, .hitRegion])
    }

    func testListScrollPositionSurvivesPortraitLandscapeChange() {
        let app = launchFixture()
        let list = app.descendants(matching: .any).matching(identifier: "workspace.items").firstMatch
        list.swipeUp()
        list.swipeUp()
        let visible = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH %@", "item.Sample"))
            .allElementsBoundByIndex.filter { $0.isHittable }
        XCTAssertFalse(visible.isEmpty)
        let anchor = visible[0].identifier
        capture(app, "list-scrolled-portrait")
        XCUIDevice.shared.orientation = .landscapeLeft
        let retained = app.buttons[anchor]
        let visibleAgain = NSPredicate(format: "hittable == true")
        expectation(for: visibleAgain, evaluatedWith: retained)
        waitForExpectations(timeout: 5)
        capture(app, "list-scrolled-landscape")
    }

    func testMaintenanceSnapshotVerifyAndExportCancellation() {
        let app = launchFixture()
        app.buttons["workspace.settings"].tap()
        let snapshot = app.buttons["maintenance.snapshot"]
        for _ in 0..<8 where !fullyVisible(snapshot, in: app) { app.swipeUp() }
        XCTAssertTrue(fullyVisible(snapshot, in: app))
        let rows = app.staticTexts.matching(identifier: "maintenance.snapshotResult")
        XCTAssertTrue(rows.firstMatch.waitForExistence(timeout: 10))
        let previousCount = rows.count
        snapshot.tap()
        // An existing automatic snapshot does not prove the manual one ended.
        expectation(for: NSPredicate { _, _ in rows.count == previousCount + 1 }, evaluatedWith: app)
        waitForExpectations(timeout: 10)
        let verify = app.buttons["maintenance.verify"]
        for _ in 0..<4 where !fullyVisible(verify, in: app) { app.swipeUp() }
        XCTAssertTrue(fullyVisible(verify, in: app))
        XCTAssertTrue(verify.isEnabled)
        verify.tap()
        let result = app.staticTexts["maintenance.verifyResult"]
        XCTAssertTrue(result.waitForExistence(timeout: 10))
        XCTAssertEqual(result.label, "Verification completed")
        capture(app, "maintenance-verification")
        let export = app.buttons["maintenance.export"]
        for _ in 0..<8 where !fullyVisible(export, in: app) { app.swipeDown() }
        XCTAssertTrue(fullyVisible(export, in: app))
        export.tap()
        let confirmationPassword = app.secureTextFields["export.password"]
        XCTAssertTrue(confirmationPassword.waitForExistence(timeout: 5))
        confirmationPassword.tap()
        confirmationPassword.typeText("synthetic mobile UI fixture")
        app.buttons["export.confirm"].tap()
        let save = app.descendants(matching: .any).matching(identifier: "Save").firstMatch
        // A fresh CI simulator can take over 10 seconds to cold-start Files.
        XCTAssertTrue(save.waitForExistence(timeout: 30))
        capture(app, "maintenance-files-export")
        cancelExport(in: app, save: save)
        expectation(for: NSPredicate(format: "exists == false"), evaluatedWith: save)
        expectation(for: NSPredicate { _, _ in self.fullyVisible(export, in: app) }, evaluatedWith: app)
        waitForExpectations(timeout: 5)
        XCTAssertTrue(export.isEnabled)
    }

    func testConnectAndUnlockFormsWithSoftwareKeyboard() {
        let app = XCUIApplication()
        app.launchArguments += ["--mobile-ui-large-text"]
        app.launch()
        app.buttons["onboarding.connect"].tap()
        let server = app.textFields["connect.server"]
        XCTAssertTrue(server.waitForExistence(timeout: 5))
        server.tap()
        server.typeText("https://example.test")
        XCTAssertTrue(app.keyboards.firstMatch.waitForExistence(timeout: 5))
        capture(app, "connect-accessibility-text-keyboard")
        app.terminate()

        let fixture = launchFixture()
        fixture.buttons["workspace.lock"].tap()
        let password = fixture.secureTextFields["master.password"]
        XCTAssertTrue(password.waitForExistence(timeout: 5))
        password.tap()
        password.typeText("synthetic mobile UI fixture")
        XCTAssertTrue(fixture.keyboards.firstMatch.waitForExistence(timeout: 5))
        capture(fixture, "unlock-keyboard")
    }

    private func launchFixture(largeText: Bool = false) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments += ["--mobile-ui-fixture"]
        if largeText { app.launchArguments += ["--mobile-ui-large-text"] }
        app.launch()
        XCTAssertTrue(app.buttons["workspace.create"].waitForExistence(timeout: 15))
        return app
    }

    private func fullyVisible(_ element: XCUIElement, in app: XCUIApplication) -> Bool {
        // isHittable can be true for a sliver clipped at the sheet's edge.
        element.isHittable && app.windows.firstMatch.frame.insetBy(dx: 0, dy: 44).contains(element.frame)
    }

    private func cancelExport(in app: XCUIApplication, save: XCUIElement) {
        if UIDevice.current.userInterfaceIdiom == .pad {
            // The tablet picker supports explicit cancellation; dragging changes its detent.
            let cancel = app.buttons["Cancel"].firstMatch
            XCTAssertTrue(cancel.waitForExistence(timeout: 5))
            cancel.tap()
        } else {
            // Phone picker Cancel AX proxies can overlap Files' search controls.
            let window = app.windows.firstMatch
            let top = window.coordinate(withNormalizedOffset: .zero).withOffset(
                CGVector(dx: window.frame.width / 2, dy: save.frame.minY - window.frame.minY - 8))
            top.press(forDuration: 0.1, thenDragTo: window.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.95)))
        }
    }

    private func capture(_ app: XCUIApplication, _ name: String) {
        let landscape = XCUIDevice.shared.orientation.isLandscape
        let window = app.windows.firstMatch
        expectation(for: NSPredicate { _, _ in
            guard app.state == .runningForeground, window.exists else { return false }
            let size = window.frame.size
            return (size.width > size.height) == landscape
        }, evaluatedWith: app)
        waitForExpectations(timeout: 5)
        let screenshot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        screenshot.name = name
        screenshot.lifetime = .keepAlways
        add(screenshot)
    }
}
