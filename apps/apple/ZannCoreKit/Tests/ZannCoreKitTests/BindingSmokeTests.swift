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

    func testSecretGeneratorCrossesTheBoundaryAndEntersTheTypedDraft() throws {
        let defaults = generatorDefaults()
        var options = defaults.password
        options.length = defaults.maxPasswordLength
        let secret = try generatePassword(options: options)
        XCTAssertEqual(secret.count, Int(defaults.maxPasswordLength))
        let draft = try ItemDraftFfi.create(typeId: "login")
        let index = try XCTUnwrap(draft.fields().firstIndex { $0.kind == .password })
        try draft.setFieldValue(index: UInt64(index), value: secret)
        XCTAssertTrue(draft.fields()[index].masked)
        XCTAssertEqual(draft.fields()[index].value.count, secret.count)

        var phrase = defaults.passphrase
        phrase.wordCount = defaults.minWords
        phrase.separator = .space
        let value = try generatePassphrase(options: phrase)
        XCTAssertEqual(value.split(separator: " ").count, Int(defaults.minWords))

        phrase.wordCount = UInt32.max
        XCTAssertThrowsError(try generatePassphrase(options: phrase)) { error in
            guard case .Generator(.wordCount, _, _) = error as? CoreError else {
                return XCTFail("expected typed generator word-count error")
            }
        }
    }

}
