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
        _ = try core.seedOfflineFixture(password: "correct horse battery")
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
        VaultModel(core: core, contents: try VaultModel.load(core), strings: Strings(language: "en"))
    }

    func testADisconnectedReplicaKeepsOfflineEditsAndReportsPendingChanges() async throws {
        let model = try makeModel()
        await model.sync()
        XCTAssertTrue(model.canSync)
        XCTAssertNotNil(model.syncError)
        XCTAssertEqual(model.visibleItems.count, 3)
        await model.refreshSyncState()
        let indicator = try XCTUnwrap(model.indicator)
        XCTAssertEqual(indicator.state, .disconnected)
        XCTAssertEqual(indicator.action, .reconnect)
        XCTAssertTrue(indicator.needsAttention)
        XCTAssertEqual(model.syncState?.link, .disconnected)
        XCTAssertEqual(model.syncState?.pendingChanges, 3)
    }

    func testAReplicaOpensItsOnlyVaultAndRefusesAnUnknownOne() async throws {
        let model = try makeModel()
        XCTAssertEqual(model.vaults.map(\.id), [try XCTUnwrap(model.vaultID)])
        XCTAssertEqual(model.vaults.first?.scope, .personal)
        XCTAssertEqual(model.vaults.first?.itemCount, 3)
        let opened = try XCTUnwrap(model.vaultID)

        await model.selectVault(opened)
        XCTAssertNil(model.error)
        await model.selectVault(UUID().uuidString.lowercased())
        XCTAssertNotNil(model.error)
        XCTAssertEqual(model.vaultID, opened)
        XCTAssertEqual(core.currentVaultId(), opened)
        XCTAssertEqual(model.visibleItems.count, 3)
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

    func testFoldersComeFromThePathsAndNarrowTheList() throws {
        let model = try makeModel()
        XCTAssertEqual(model.folders.tree.map(\.path), ["Personal", "Work"])
        XCTAssertEqual(model.folders.itemsWithoutFolder, 1)

        model.folder = .path(path: "Work")
        XCTAssertEqual(model.visibleItems.map(\.title), ["GitHub"])
        model.folder = .withoutFolder
        XCTAssertEqual(model.visibleItems.map(\.title), ["Bank"])
    }

    func testScrollingLoadsEveryItemPastTheFirstPage() async throws {
        try createVaultPastTheFirstPage()
        let model = try makeModel()
        XCTAssertEqual(model.totalCount, 254)
        XCTAssertEqual(model.visibleItems.count, 200)
        XCTAssertFalse(model.visibleItems.contains { $0.title == "Hetzner" })

        // Rows far from the end load nothing.
        model.itemAppeared(try XCTUnwrap(model.visibleItems.first).id)
        XCTAssertFalse(model.loadingMore)
        model.itemAppeared(try XCTUnwrap(model.visibleItems.last).id)
        try await settled(model)

        XCTAssertEqual(model.visibleItems.count, 254)
        XCTAssertEqual(Set(model.visibleItems.map(\.id)).count, 254)
        XCTAssertTrue(model.visibleItems.contains { $0.title == "Hetzner" })
        XCTAssertEqual(model.folders.tree.map(\.path), ["Cloud", "Filler", "Personal", "Work"])
    }

    func testSearchFindsAnItemPastTheLoadedPage() async throws {
        try createVaultPastTheFirstPage()
        let model = try makeModel()
        XCTAssertFalse(model.visibleItems.contains { $0.title == "Hetzner" })

        model.query = "hetz"
        // Until the core answers, only the loaded page narrows.
        XCTAssertTrue(model.searching)
        XCTAssertEqual(model.visibleItems.count, 0)
        XCTAssertNil(model.searchMatchCount)
        try await settled(model)
        XCTAssertEqual(model.visibleItems.map(\.title), ["Hetzner"])
        let counts = Dictionary(uniqueKeysWithValues: model.categories.map { ($0.id, $0.count) })
        XCTAssertEqual(counts["all"], 1)
        XCTAssertEqual(model.searchMatchCount, 1)
        XCTAssertEqual(model.searchedQuery, "hetz")
        model.categoryID = "note"
        XCTAssertEqual(model.searchMatchCount, 0)
        model.categoryID = "all"
        model.folder = .path(path: "Cloud")
        XCTAssertEqual(model.searchMatchCount, 1)
        model.folder = .withoutFolder
        XCTAssertEqual(model.searchMatchCount, 0)
        model.folder = .any

        model.query = ""
        try await settled(model)
        XCTAssertNil(model.searchMatchCount)
        XCTAssertEqual(model.visibleItems.count, 200)
        XCTAssertEqual(model.totalCount, 254)
    }

    func testASparseCategoryLoadsPagesUntilItsItemsShow() async throws {
        try createVaultPastTheFirstPage()
        let model = try makeModel()
        model.categoryID = "login"
        try await settled(model)
        XCTAssertEqual(Set(model.visibleItems.map(\.title)), ["Hetzner", "Bank", "GitHub"])
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

    func testNewItemTakesTheCategoryTypeAndIsShownAfterSave() async throws {
        let model = try makeModel()
        model.categoryID = "note"
        model.startCreating()
        let editor = try XCTUnwrap(model.editor)
        XCTAssertEqual(editor.mode, .create)
        XCTAssertEqual(editor.typeID, "note")
        editor.name = "Shopping"
        editor.folder = "Personal"
        editor.setValue(try index(of: "text", in: editor), "eggs")

        await model.saveEditor()

        XCTAssertNil(model.editor)
        XCTAssertEqual(model.categoryID, "note")
        XCTAssertEqual(model.visibleItems.map(\.title).sorted(), ["Groceries", "Shopping"])
        let detail = try await loadedDetail(model)
        XCTAssertEqual(detail.title, "Shopping")
        XCTAssertEqual(detail.fields.first { $0.key == "text" }?.value, "eggs")
    }

    func testCategoryWithSeveralTypesCreatesItsFirstType() throws {
        let model = try makeModel()
        model.categoryID = "infra"
        model.startCreating()
        XCTAssertEqual(model.editor?.typeID, "ssh_key")
    }

    func testEmptyCategoryActionOpensItsAdvertisedType() throws {
        let model = try makeModel()
        model.categoryID = "card"
        XCTAssertTrue(model.visibleItems.isEmpty)
        let category = try XCTUnwrap(model.categories.first { $0.id == model.categoryID })
        let action = try XCTUnwrap(category.createAction)
        XCTAssertEqual(Strings(language: "en")(action.labelKey), "Create card")
        model.startCreating(typeID: action.typeId)
        XCTAssertEqual(model.editor?.typeID, "card")
    }

    func testSavedItemOutsideTheFilterResetsTheList() async throws {
        let model = try makeModel()
        model.categoryID = "note"
        model.folder = .path(path: "Personal")
        model.query = "gro"
        model.startCreating(typeID: "login")
        let editor = try XCTUnwrap(model.editor)
        editor.name = "Mail"
        editor.setValue(try index(of: "username", in: editor), "carol")

        await model.saveEditor()

        XCTAssertEqual(model.categoryID, "all")
        XCTAssertEqual(model.folder, .any)
        XCTAssertEqual(model.query, "")
        let detail = try await loadedDetail(model)
        XCTAssertEqual(detail.title, "Mail")
    }

    func testEditingKeepsUntouchedFieldsAndShowsTheStoredVersion() async throws {
        let model = try makeModel()
        let github = try XCTUnwrap(model.visibleItems.first { $0.title == "GitHub" })
        model.select(github.id)
        _ = try await loadedDetail(model)

        await model.startEditing()
        let editor = try XCTUnwrap(model.editor)
        XCTAssertEqual(editor.mode, .edit(id: github.id))
        XCTAssertEqual(editor.name, "GitHub")
        XCTAssertEqual(editor.folder, "Work")
        XCTAssertEqual(editor.mainFieldIndices.map { editor.fields[$0].key }, ["username", "password", "url"])
        XCTAssertEqual(editor.additionalFieldIndices.map { editor.fields[$0].key }, ["totp"])
        editor.name = "GitHub Enterprise"
        editor.folder = "Work/Accounts"
        editor.setValue(try index(of: "username", in: editor), "alice2")

        await model.saveEditor()

        XCTAssertNil(model.editor)
        XCTAssertEqual(model.selectedItemID, github.id)
        let detail = try await loadedDetail(model)
        XCTAssertEqual(detail.title, "GitHub Enterprise")
        XCTAssertEqual(detail.path, "Work/Accounts/GitHub Enterprise")
        let values = Dictionary(uniqueKeysWithValues: detail.fields.map { ($0.key, $0.value) })
        XCTAssertEqual(values["username"], "alice2")
        XCTAssertEqual(values["password"], "hunter2")
        XCTAssertEqual(values["totp"], "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(model.visibleItems.count, 3)
    }

    func testInvalidDraftStaysOpenWithTheTranslatedError() async throws {
        let model = try makeModel()
        model.startCreating(typeID: "note")
        let editor = try XCTUnwrap(model.editor)
        editor.name = "Empty"
        while !editor.fields.isEmpty {
            editor.removeField(0)
        }

        await model.saveEditor()

        XCTAssertTrue(model.editor === editor)
        XCTAssertEqual(editor.error, .translated(key: "errors.fields_required"))
        XCTAssertEqual(model.visibleItems.count, 3)
    }

    func testAnEmptyNameCannotSaveUnderTheFolderName() async throws {
        let model = try makeModel()
        model.startCreating(typeID: "login")
        let editor = try XCTUnwrap(model.editor)
        editor.folder = "Work"
        await model.saveEditor()
        XCTAssertTrue(model.editor === editor)
        XCTAssertEqual(editor.error, .translated(key: "errors.item_name_invalid"))
        XCTAssertEqual(model.visibleItems.count, 3)
    }

    func testAddingAMissingStandardFieldUsesTheSchemaAndPreservesOtherFields() throws {
        let editor = try ItemEditorModel.create(typeID: "login")
        editor.setValue(try index(of: "password", in: editor), "fixture-password")
        editor.removeField(try index(of: "url", in: editor))
        let definition = try XCTUnwrap(editor.missingMainFields.first)
        XCTAssertEqual(definition.key, "url")
        editor.addField(definition)
        XCTAssertTrue(editor.missingMainFields.isEmpty)
        XCTAssertEqual(editor.fields[try index(of: "url", in: editor)].kind, .url)
        XCTAssertEqual(editor.fields[try index(of: "password", in: editor)].value, "fixture-password")
    }

    private func index(of key: String, in editor: ItemEditorModel) throws -> Int {
        try XCTUnwrap(editor.fields.firstIndex { $0.key == key }, "no \(key) field")
    }

    private func loadedDetail(_ model: VaultModel) async throws -> VaultModel.Detail {
        for _ in 0..<100 {
            if !model.detailLoading, let detail = model.detail { return detail }
            XCTAssertNil(model.error)
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        struct Timeout: Error {}
        XCTFail("detail did not load within 5 seconds")
        throw Timeout()
    }

    /// 254 items, newest first: 250 notes fill the first page, so the login
    /// created before them sits past it.
    private func createVaultPastTheFirstPage() throws {
        try createItem("login", path: "Cloud/Hetzner", values: ["username": "root"])
        for index in 0..<250 {
            try createItem("note", path: "Filler/Note \(index)", values: ["text": "filler"])
        }
    }

    /// Waits until no search or page is loading.
    private func settled(_ model: VaultModel) async throws {
        for _ in 0..<200 {
            if !model.searching && !model.loadingMore { return }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        struct Timeout: Error {}
        XCTFail("the list did not settle within 10 seconds")
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
