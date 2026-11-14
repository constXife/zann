import XCTest
@testable import ZannCoreKit

/// Proves the generated bindings link against libzann_ffi.a and reach the Rust
/// exports; behaviour itself is tested in Rust.
final class BindingSmokeTests: XCTestCase {
    func testItemTypeSchemasCrossTheBoundary() {
        XCTAssertFalse(itemTypeSchemas().isEmpty)
    }

    func testEmptyCategoryCreationCrossesTheBoundary() throws {
        let categories = categoryViews(counts: ItemCountsFfi(all: 0, trash: 0, byType: []), scope: .personal)
        let note = try XCTUnwrap(categories.first { $0.id == "note" }?.createAction)
        XCTAssertEqual(note.typeId, "note")
        XCTAssertEqual(note.labelKey, "create.actions.note")
        XCTAssertNil(categories.first { $0.id == "trash" }?.createAction)
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
