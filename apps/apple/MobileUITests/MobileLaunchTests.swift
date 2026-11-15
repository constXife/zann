import XCTest

final class MobileLaunchTests: XCTestCase {
    @MainActor
    func testAppLaunchesIntoSharedOnboarding() {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.staticTexts["onboarding.title"].waitForExistence(timeout: 10))
        XCTAssertEqual(app.staticTexts["onboarding.title"].label, "Zann")
    }
}
