import Foundation
import ZannCoreKit

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
    @Published private(set) var visibleItems: [ItemSummary] = []
    @Published private(set) var totalCount: UInt64 = 0
    @Published private(set) var detail: Detail?
    @Published private(set) var error: String?

    @Published var categoryID: String {
        didSet { if categoryID != oldValue { refreshVisible() } }
    }

    @Published var query = "" {
        didSet { if query != oldValue { refreshVisible() } }
    }

    @Published private(set) var selectedItemID: String?

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

    func select(_ id: String?) {
        guard id != selectedItemID else { return }
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
        refreshVisible()
    }

    private func refreshVisible() {
        let filter = ItemFilterFfi(categoryId: categoryID, folder: .any, query: query)
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
