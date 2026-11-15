import XCTest
import ZannCoreKit
#if os(iOS)
@testable import ZannMobile
#else
@testable import Zann
#endif

@MainActor
final class MobileNavigationTests: XCTestCase {
    func testRotationAndCompactWindowsKeepSelectionScrollAndDraft() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let core = try createCore(dbPath: directory.appendingPathComponent("local.sqlite").path,
                                  keystore: MemoryKeystore(), secretStore: MemorySecretStore())
        _ = try core.seedOfflineFixture(password: "layout test password")
        let draft = try ItemDraftFfi.create(typeId: "login")
        try draft.setLocation(name: "Selected item", folder: "Work")
        let item = try core.itemCreate(create: draft.createRequest())
        let vault = VaultModel(core: core, contents: try VaultModel.load(core), strings: Strings(language: "en"))
        let navigation = MobileNavigation()
        vault.select(item.id)
        navigation.selectionChanged(item.id)
        // Start a second draft while keeping the selected card underneath.
        vault.startCreating(typeID: "note")
        let editor = try XCTUnwrap(vault.editor)
        editor.name = "Unsaved mobile draft"
        let storage = vault.storageID
        let selectedVault = vault.vaultID
        navigation.listAnchor = item.id

        for (width, regular, tablet, largeText, expected) in [
            (1200.0, true, true, false, MobileNavigation.Layout.columns),
            (600.0, true, true, false, .stack),
            (844.0, false, false, false, .stack),
            (956.0, true, false, false, .stack),
            (1200.0, true, true, true, .stack),
            (1200.0, true, true, false, .columns),
        ] {
            navigation.resize(to: MobileNavigation.layout(width: width, regular: regular, tablet: tablet, accessibilityText: largeText))
            XCTAssertEqual(navigation.layout, expected)
            XCTAssertEqual(navigation.path, [.items, .detail])
            XCTAssertEqual(navigation.listAnchor, item.id)
            XCTAssertEqual(vault.selectedItemID, item.id)
            XCTAssertEqual(vault.vaultID, selectedVault)
            XCTAssertEqual(vault.storageID, storage)
            XCTAssertTrue(vault.editor === editor)
            XCTAssertEqual(editor.name, "Unsaved mobile draft")
        }
        // Going back preserves selection, but the next layout change must
        // respect the user's list route rather than reopening the detail.
        navigation.path.removeLast()
        navigation.resize(to: .stack)
        XCTAssertEqual(navigation.path, [.items])
        XCTAssertEqual(vault.selectedItemID, item.id)
        vault.cancelEditing()
        _ = try core.lock()
    }

    func testRemovedSelectionPopsDetailAndContextSwitchDropsOldScrollBookmark() {
        let navigation = MobileNavigation()
        navigation.showDetail()
        navigation.listAnchor = "old-context-item"
        navigation.selectionChanged(nil)
        XCTAssertEqual(navigation.path, [.items])
        navigation.contextChanged()
        XCTAssertNil(navigation.listAnchor)
        XCTAssertEqual(navigation.path, [.items])
    }

    func testOldRevealTimersCannotAffectNewRevealsAndResetMasksEveryField() async throws {
        let reveal = FieldRevealState()
        reveal.toggle(0, seconds: 1)
        reveal.reset()
        reveal.toggle(0, seconds: 0)
        reveal.toggle(1, seconds: 1)
        try await Task.sleep(nanoseconds: 1_100_000_000)
        XCTAssertEqual(reveal.revealed, [0])
        reveal.reset()
        XCTAssertTrue(reveal.revealed.isEmpty)
    }
}
