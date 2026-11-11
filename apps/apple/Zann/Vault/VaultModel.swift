import Foundation
import ZannCoreKit

/// First page only; paging and server-side search come in a later slice.
private let itemsPageLimit: UInt32 = 200

/// One unlocked vault: the loaded page, the sidebar categories, the visible
/// list and the selected item's projected fields. Categories, filtering and
/// field projection come from zann-ui-core; this type only holds selection and
/// sequences the blocking calls. Dropping it on lock drops every secret it held.
@MainActor
final class VaultModel: ObservableObject {
    struct Detail {
        let id: String
        let title: String
        let path: String
        let typeID: String
        let fields: [ItemDetailFieldFfi]
    }

    @Published private(set) var categories: [CategoryViewFfi] = []
    @Published private(set) var folders = FolderTreeFfi(itemsWithoutFolder: 0, tree: [])
    @Published private(set) var visibleItems: [ItemSummary] = []
    @Published private(set) var totalCount: UInt64 = 0
    @Published private(set) var detail: Detail?
    @Published private(set) var error: String?

    @Published var categoryID: String {
        didSet { if categoryID != oldValue { refreshVisible() } }
    }

    /// Narrows the list to a folder and everything below it; the sidebar
    /// pairs it with the "all" category.
    @Published var folder = FolderFilterFfi.any {
        didSet { if folder != oldValue { refreshVisible() } }
    }

    @Published var query = "" {
        didSet { if query != oldValue { refreshVisible() } }
    }

    @Published private(set) var selectedItemID: String?
    /// The open create or edit form; at most one at a time.
    @Published private(set) var editor: ItemEditorModel?

    private let core: CoreFacade
    private var items: [ItemSummary] = []
    private var counts: ItemCountsFfi
    /// Bumped on every selection so a slow load cannot show a previous item.
    private var selection = 0

    init(core: CoreFacade, page: ItemPage) {
        self.core = core
        counts = page.counts
        categoryID = "all"
        apply(page)
    }

    /// The first page of the current vault. The trash category filters
    /// client-side, so deleted items load too.
    nonisolated static func loadPage(_ core: CoreFacade) throws -> ItemPage {
        try core.itemsList(
            filter: ItemsFilter(query: nil, includeDeleted: true),
            page: Page(limit: itemsPageLimit, cursor: nil)
        )
    }

    func select(_ id: String?) {
        guard id != selectedItemID else { return }
        show(id)
    }

    /// A new item of `typeID`, or of the type zann-ui-core picks for the
    /// selected category.
    func startCreating(typeID: String? = nil) {
        guard editor == nil else { return }
        let type = typeID ?? createTypeForCategory(categoryId: categoryID)
        open { try ItemEditorModel.create(typeID: type) }
    }

    func startEditing() async {
        guard editor == nil, let id = detail?.id else { return }
        let core = core
        let result = await Task.detached(priority: .userInitiated) {
            Result { try core.itemGet(id: id) }
        }.value
        open { try ItemEditorModel.edit(try result.get()) }
    }

    func cancelEditing() {
        editor = nil
    }

    /// Saves the open form, then reloads the page and shows the saved item.
    func saveEditor() async {
        guard let editor, let item = await editor.save(with: core) else { return }
        self.editor = nil
        let core = core
        let result = await Task.detached(priority: .userInitiated) {
            Result { try Self.loadPage(core) }
        }.value
        switch result {
        case .success(let page): apply(page)
        case .failure(let failure):
            error = describe(failure)
            return
        }
        // A saved item can fall outside the current category, folder or search.
        if !visibleItems.contains(where: { $0.id == item.id }) {
            query = ""
            folder = .any
            categoryID = "all"
        }
        show(item.id)
    }

    private func open(_ make: () throws -> ItemEditorModel) {
        do {
            editor = try make()
        } catch {
            self.error = describe(error)
        }
    }

    /// Loads `id` into the detail pane even when it is already selected, so a
    /// save shows the stored version.
    private func show(_ id: String?) {
        selectedItemID = id
        detail = nil
        error = nil
        selection += 1
        guard let id else { return }
        let token = selection
        let core = core
        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Result { try Self.loadDetail(core, id: id) }
            }.value
            guard token == selection else { return }
            switch result {
            case .success(let detail): self.detail = detail
            case .failure(let failure): error = describe(failure)
            }
        }
    }

    private func apply(_ page: ItemPage) {
        items = page.items
        counts = page.counts
        totalCount = page.totalCount
        categories = categoryViews(counts: counts, scope: .personal)
        folders = buildFolderTree(items: items)
        refreshVisible()
    }

    private func refreshVisible() {
        let filter = ItemFilterFfi(categoryId: categoryID, folder: folder, query: query)
        visibleItems = filterItems(items: items, filter: filter).map { items[Int($0)] }
        if let selectedItemID, !visibleItems.contains(where: { $0.id == selectedItemID }) {
            select(nil)
        }
    }

    private nonisolated static func loadDetail(_ core: CoreFacade, id: String) throws -> Detail {
        let item = try core.itemGet(id: id)
        return Detail(
            id: item.id,
            title: item.title,
            path: item.path,
            typeID: item.typeId,
            fields: try projectItemFields(payloadJson: item.payloadJson)
        )
    }
}
