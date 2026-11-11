import XCTest
@testable import ZannCoreKit

/// Proves the generated bindings link against libzann_ffi.a and reach the Rust
/// exports; behaviour itself is tested in Rust.
final class BindingSmokeTests: XCTestCase {
    func testItemTypeSchemasCrossTheBoundary() {
        XCTAssertFalse(itemTypeSchemas().isEmpty)
    }

    func testServerUrlNormalizationCrossesTheBoundary() {
        XCTAssertEqual(
            normalizeServerUrl(value: "  https://zann.example  "),
            "https://zann.example"
        )
    }

    func testDevicePreferenceDefaultsAreStable() {
        XCTAssertEqual(devicePreferencesDefault(), devicePreferencesDefault())
    }
}
