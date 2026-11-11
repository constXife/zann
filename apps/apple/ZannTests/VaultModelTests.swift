import XCTest
import ZannCoreKit
@testable import Zann

/// VaultModel over the real core: categories and filtering come from
/// zann-ui-core, details from the stored payload, and a stale selection never
/// wins over the current one.
@MainActor
final class VaultModelTests: XCTestCase {
    private var directory: URL!
    private var core: CoreFacade!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("zann-vault-model-\(UUID().uuidString)", isDirectory: true)
        core = try createCore(
            dbPath: directory.appendingPathComponent("local.sqlite").path,
            keystore: MemoryKeystore(),
            secretStore: MemorySecretStore()
        )
        _ = try core.initializeMasterPassword(password: "correct horse battery")
        try createItem("login", path: "Work/GitHub", values: [
            "username": "alice", "password": "hunter2", "totp": "JBSWY3DPEHPK3PXP",
        ])
        try createItem("login", path: "Bank", values: ["username": "bob", "password": "s3cret"])
        try createItem("note", path: "Personal/Groceries", values: ["notes": "milk"])
    }

    override func tearDownWithError() throws {
        core = nil
        try? FileManager.default.removeItem(at: directory)
    }

    private func makeModel() throws -> VaultModel {
        let page = try core.itemsList(
            filter: ItemsFilter(query: nil, includeDeleted: true),
            page: Page(limit: 200, cursor: nil)
        )
        return VaultModel(core: core, page: page)
    }

    func testCategoriesCountTheLoadedItems() throws {
        let model = try makeModel()
        let counts = Dictionary(uniqueKeysWithValues: model.categories.map { ($0.id, $0.count) })
        XCTAssertEqual(counts["all"], 3)
        XCTAssertEqual(counts["login"], 2)
        XCTAssertEqual(counts["note"], 1)
        XCTAssertEqual(model.categoryID, "all")
        XCTAssertEqual(model.visibleItems.count, 3)
    }

    func testCategoryAndSearchNarrowTheList() throws {
        let model = try makeModel()
        model.categoryID = "note"
        XCTAssertEqual(model.visibleItems.map(\.title), ["Groceries"])

        model.categoryID = "all"
        model.query = "git"
        XCTAssertEqual(model.visibleItems.map(\.title), ["GitHub"])
    }

    func testSelectionProjectsFieldsWithMaskingAndTotp() async throws {
        let model = try makeModel()
        let github = try XCTUnwrap(model.visibleItems.first { $0.title == "GitHub" })
        model.select(github.id)
        let detail = try await loadedDetail(model)

        XCTAssertEqual(detail.title, "GitHub")
        XCTAssertEqual(detail.fields.map(\.key), ["username", "password", "totp", "url"])
        XCTAssertFalse(detail.fields[0].masked)
        XCTAssertTrue(detail.fields[1].masked)
        XCTAssertNotNil(detail.fields[2].totp)
    }

    func testFilteringOutTheSelectedItemClearsTheDetail() async throws {
        let model = try makeModel()
        let github = try XCTUnwrap(model.visibleItems.first { $0.title == "GitHub" })
        model.select(github.id)
        _ = try await loadedDetail(model)

        model.categoryID = "note"
        XCTAssertNil(model.selectedItemID)
        XCTAssertNil(model.detail)
    }

    func testLatestSelectionWins() async throws {
        let model = try makeModel()
        let github = try XCTUnwrap(model.visibleItems.first { $0.title == "GitHub" })
        let bank = try XCTUnwrap(model.visibleItems.first { $0.title == "Bank" })
        model.select(github.id)
        model.select(bank.id)
        let detail = try await loadedDetail(model)
        XCTAssertEqual(detail.title, "Bank")
        // Give the superseded load time to land; it must not replace Bank.
        try await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertEqual(model.detail?.title, "Bank")
    }

    private func loadedDetail(_ model: VaultModel) async throws -> VaultModel.Detail {
        for _ in 0..<100 {
            if let detail = model.detail { return detail }
            XCTAssertNil(model.error)
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        struct Timeout: Error {}
        XCTFail("detail did not load within 5 seconds")
        throw Timeout()
    }

    private func createItem(_ typeID: String, path: String, values: [String: String]) throws {
        let draft = try ItemDraftFfi.create(typeId: typeID)
        draft.setPath(path: path)
        for (key, value) in values {
            var index = draft.fields().firstIndex { $0.key == key }
            if index == nil {
                draft.addField()
                index = draft.fields().count - 1
                try draft.setFieldKey(index: UInt64(index!), key: key)
                try draft.setFieldKind(index: UInt64(index!), kind: key == "totp" ? .otp : .text)
            }
            try draft.setFieldValue(index: UInt64(index!), value: value)
        }
        _ = try core.itemCreate(create: draft.createRequest())
    }
}
