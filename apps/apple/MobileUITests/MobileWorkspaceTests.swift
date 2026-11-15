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
        let copy = app.buttons["detail.copy.password"]
        copy.tap()
        expectation(for: NSPredicate(format: "value CONTAINS %@", "Copied"), evaluatedWith: copy)
        waitForExpectations(timeout: 5)
        capture(app, "detail-portrait-masked")
        reveal.tap()
        XCTAssertEqual(reveal.label, "Hide")
        XCUIDevice.shared.orientation = .landscapeLeft
        XCTAssertTrue(app.buttons["detail.reveal.password"].waitForExistence(timeout: 5))
        expectation(for: NSPredicate(format: "label == %@", "Reveal"), evaluatedWith: app.buttons["detail.reveal.password"])
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
        for _ in 0..<8 where !snapshot.isHittable { app.swipeUp() }
        XCTAssertTrue(snapshot.isHittable)
        snapshot.tap()
        XCTAssertTrue(app.staticTexts["maintenance.snapshotResult"].firstMatch.waitForExistence(timeout: 10))
        let verify = app.buttons["maintenance.verify"]
        for _ in 0..<4 where !verify.isHittable { app.swipeUp() }
        verify.tap()
        let result = app.staticTexts["maintenance.verifyResult"]
        XCTAssertTrue(result.waitForExistence(timeout: 10))
        XCTAssertEqual(result.label, "Verification completed")
        capture(app, "maintenance-verification")
        let export = app.buttons["maintenance.export"]
        for _ in 0..<8 where !export.isHittable { app.swipeDown() }
        export.tap()
        let warning = app.alerts["Plain JSON Export"]
        XCTAssertTrue(warning.waitForExistence(timeout: 5))
        warning.buttons["Export JSON"].tap()
        let cancel = app.buttons["Cancel"].firstMatch
        XCTAssertTrue(cancel.waitForExistence(timeout: 10))
        capture(app, "maintenance-files-export")
        cancel.tap()
        XCTAssertTrue(export.waitForExistence(timeout: 5))
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

    private func capture(_ app: XCUIApplication, _ name: String) {
        let landscape = XCUIDevice.shared.orientation.isLandscape
        expectation(for: NSPredicate { _, _ in
            let size = app.windows.firstMatch.frame.size
            return (size.width > size.height) == landscape
        }, evaluatedWith: app)
        waitForExpectations(timeout: 5)
        let screenshot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        screenshot.name = name
        screenshot.lifetime = .keepAlways
        add(screenshot)
    }
}
