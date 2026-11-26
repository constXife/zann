import Foundation
import ZannCoreKit

/// A history inspector belongs to one item in one unlocked vault.
@MainActor
final class ItemHistoryModel: ObservableObject {
    let itemID: String
    let title: String
    private let path: String
    private let core: CoreFacade
    @Published private(set) var entries: [ItemHistorySummaryFfi] = []
    @Published private(set) var selected: ItemHistorySummaryFfi?
    @Published private(set) var preview: ItemDetailViewFfi?
    @Published private(set) var loadingList = true
    @Published private(set) var loadingVersion = false
    @Published private(set) var restoring = false
    @Published private(set) var failure: Error?
    private(set) var previewGeneration = 0
    private var listGeneration = 0
    private var active = true

    init(item: ItemDetailViewFfi, core: CoreFacade) {
        itemID = item.id
        title = item.title
        path = item.path
        self.core = core
    }

    func close() {
        active = false
        entries = []
        resetPreview()
    }

    func refresh() async {
        guard active, !restoring else { return }
        listGeneration += 1
        let generation = listGeneration
        let result = await BlockingCore.run { [core, itemID] in
            Result { try core.itemHistoryList(id: itemID, limit: 20) }
        }
        guard active, !restoring, listGeneration == generation else { return }
        loadingList = false
        switch result {
        case .failure(let error):
            failure = error
        case .success(let entries):
            self.entries = entries
            failure = nil
            let entry = entries.first { $0.id == selected?.id } ?? entries.first
            guard let entry else { resetPreview(); return }
            if entry.id == selected?.id, entry.checksum == selected?.checksum,
               preview != nil || loadingVersion {
                selected = entry
            } else {
                await select(entry)
            }
        }
    }

    func select(_ entry: ItemHistorySummaryFfi) async {
        guard active, !restoring, entries.contains(where: {
            $0.id == entry.id && $0.checksum == entry.checksum
        }) else { return }
        resetPreview()
        selected = entry
        loadingVersion = true
        failure = nil
        let generation = previewGeneration
        let result = await BlockingCore.run { [core, itemID] in
            Result { try core.itemHistoryGet(id: itemID, entryId: entry.id) }
        }
        guard active, previewGeneration == generation else { return }
        loadingVersion = false
        switch result {
        case .success(let version):
            guard version.version == entry.version, version.checksum == entry.checksum else {
                failure = CoreError.Sync(kind: "history_changed", message: "The selected version changed.")
                return
            }
            preview = ItemDetailViewFfi(id: itemID, title: title, path: path,
                                        typeId: version.typeId, fields: version.fields)
        case .failure(let error): failure = error
        }
    }

    func restore(_ confirmed: ItemHistorySummaryFfi) async -> Bool {
        guard active, !restoring, preview != nil,
              selected?.id == confirmed.id, selected?.checksum == confirmed.checksum else { return false }
        restoring = true
        listGeneration += 1
        defer { restoring = false }
        let result = await BlockingCore.run { [core, itemID] in
            Result { try core.itemHistoryRestore(id: itemID, entryId: confirmed.id, checksum: confirmed.checksum) }
        }
        guard active else { return false }
        switch result {
        case .success: return true
        case .failure(let error):
            failure = error
            return false
        }
    }

    private func resetPreview() {
        previewGeneration += 1
        preview = nil
        selected = nil
        loadingVersion = false
    }
}
