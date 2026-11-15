import XCTest

/// Explicit real-device acceptance. No fixture, credentials or vault mutations.
@MainActor
final class LiveConnectionTests: XCTestCase {
    /// The device owner completes provider credentials, master unlock and
    /// biometrics. The test only drives navigation and reads synchronization UI.
    func testInteractiveSignInAndInitialSync() async throws {
        guard ProcessInfo.processInfo.environment["ZANN_LIVE_INTERACTIVE"] == "1",
              let address = ProcessInfo.processInfo.environment["ZANN_LIVE_SERVER"],
              let issuer = ProcessInfo.processInfo.environment["ZANN_LIVE_ISSUER"],
              let issuerHost = URL(string: issuer)?.host else {
            throw XCTSkip("Explicit server, issuer and interactive device acceptance are required")
        }
        continueAfterFailure = false
        executionTimeAllowance = 420
        let app = XCUIApplication()
        app.activate()
        let workspace = app.buttons["workspace.settings"].firstMatch
        if !workspace.waitForExistence(timeout: 2) {
            let onboarding = app.buttons["onboarding.connect"]
            if onboarding.exists { onboarding.tap() }
            let server = app.textFields["connect.server"]
            if server.exists {
                server.tap()
                if let existing = server.value as? String, existing.hasPrefix("http") {
                    server.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: existing.count))
                }
                server.typeText(address)
                app.buttons["connect.continue"].tap()
                let oidc = app.buttons["connect.method.oidc"]
                if oidc.waitForExistence(timeout: 3) { oidc.tap() }

                let system = XCUIApplication(bundleIdentifier: "com.apple.springboard")
                let consent = system.alerts.firstMatch
                if consent.waitForExistence(timeout: 10) {
                    XCTAssertTrue(consent.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", issuerHost)).firstMatch.exists)
                    consent.buttons.matching(NSPredicate(format: "label IN %@", ["Продолжить", "Continue"])).firstMatch.tap()
                }
            }
        }
        let error = app.staticTexts["connect.error"]
        let signedIn = expectation(for: NSPredicate { _, _ in workspace.exists || error.exists }, evaluatedWith: app)
        await fulfillment(of: [signedIn], timeout: 300)
        XCTAssertFalse(error.exists, error.exists ? error.label : "")
        XCTAssertTrue(workspace.exists, "The owner must complete sign-in/unlock on the device")

        let syncButtons = app.buttons.matching(identifier: "workspace.sync")
        let visibleSync = expectation(for: NSPredicate { _, _ in
            syncButtons.allElementsBoundByIndex.contains { $0.isHittable }
        }, evaluatedWith: app)
        await fulfillment(of: [visibleSync], timeout: 15)
        let sync = try XCTUnwrap(syncButtons.allElementsBoundByIndex.first { $0.isHittable })
        sync.tap()
        let status = app.descendants(matching: .any).matching(identifier: "sync.status.sync.synced").firstMatch
        let syncError = app.staticTexts["sync.error"]
        let lastSynced = app.staticTexts.matching(NSPredicate(format: "identifier BEGINSWITH %@", "sync.lastSynced.")).firstMatch
        let synced = expectation(for: NSPredicate { _, _ in (status.exists && lastSynced.exists) || syncError.exists }, evaluatedWith: app)
        await fulfillment(of: [synced], timeout: 60)
        XCTAssertFalse(syncError.exists, syncError.exists ? syncError.label : "")
        XCTAssertTrue(status.exists)
        XCTAssertTrue(lastSynced.exists)
        let previous = lastSynced.identifier
        let run = app.buttons["sync.run"]
        XCTAssertTrue(run.isEnabled)
        run.tap()
        let refreshed = expectation(for: NSPredicate { _, _ in
            syncError.exists || (status.exists && lastSynced.exists && lastSynced.identifier != previous)
        }, evaluatedWith: app)
        await fulfillment(of: [refreshed], timeout: 60)
        XCTAssertFalse(syncError.exists, syncError.exists ? syncError.label : "")
        XCTAssertNotEqual(lastSynced.identifier, previous, "Manual sync must persist a new success timestamp")
        let capture = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        capture.name = "live-device-manual-sync"
        capture.lifetime = .keepAlways
        add(capture)
    }

    func testNativeTrustAndConnectProbe() async throws {
        continueAfterFailure = false
        guard let address = ProcessInfo.processInfo.environment["ZANN_LIVE_SERVER"] else {
            throw XCTSkip("Set TEST_RUNNER_ZANN_LIVE_SERVER for signed-device acceptance")
        }
        let url = try XCTUnwrap(URL(string: address))
        XCTAssertEqual(url.scheme, "https")

        // Compare Apple's trust evaluation with the real shared-core transport.
        // No custom CA, challenge delegate or credential is supplied here.
        var request = URLRequest(url: url, timeoutInterval: 15)
        request.httpMethod = "HEAD"
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let (_, response) = try await session.data(for: request)
        XCTAssertNotNil(response as? HTTPURLResponse, "Native HTTPS must complete before probing the Rust transport")

        let app = XCUIApplication()
        app.launch()
        defer {
            let capture = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
            capture.name = "live-server-connect-probe"
            capture.lifetime = .keepAlways
            add(capture)
        }
        let onboarding = app.buttons["onboarding.connect"]
        if onboarding.waitForExistence(timeout: 2) { onboarding.tap() }
        let server = app.textFields["connect.server"]
        XCTAssertTrue(server.waitForExistence(timeout: 5), "Expected an unauthenticated connect screen")
        server.tap()
        if let existing = server.value as? String, existing.hasPrefix("http") {
            server.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: existing.count))
        }
        server.typeText(address)
        app.buttons["connect.continue"].tap()

        let unavailable = app.staticTexts.containing(NSPredicate(format: "label CONTAINS %@", "transport_unavailable")).firstMatch
        let method = app.buttons.matching(NSPredicate(format: "identifier BEGINSWITH %@", "connect.method.")).firstMatch
        let browser = app.staticTexts["connect.browser"]
        let password = app.secureTextFields["connect.password"]
        let probe = expectation(for: NSPredicate { _, _ in unavailable.exists || method.exists || browser.exists || password.exists }, evaluatedWith: app)
        await fulfillment(of: [probe], timeout: 20)
        XCTAssertFalse(unavailable.exists, "Native HTTPS succeeded, but the Rust connect probe returned transport_unavailable")
        XCTAssertTrue(method.exists || browser.exists || password.exists, "Expected an authentication method or automatic single-method sign-in")
    }
}
