import ZannCoreKit

/// Blocking adapter reads kept off the UI actor. The core owns selection,
/// key checks, storage/account binding and preferred-vault policy.
enum VaultContextLoader {
    enum Selection {
        case loaded(VaultModel.Contents)
        case refused(Error)
        case unreadable(Error)
    }

    static func select(_ core: CoreFacade, storage: StorageSummaryFfi) -> Selection {
        do {
            try core.setCurrentStorage(id: storage.id)
        } catch {
            return .refused(error)
        }
        do {
            return .loaded(try load(core, query: "", keeping: 0))
        } catch {
            return .unreadable(error)
        }
    }

    static func load(_ core: CoreFacade, query: String, keeping: Int) throws -> VaultModel.Contents {
        let storageID = core.currentStorageId()
        let page = try page(core, query: query, cursor: nil, limit: UInt32(max(Int(itemsPageLimit), keeping)))
        let vaults = try core.listVaults()
        let storages = try core.listStorages()
        let syncState = try core.storageSyncState(storageId: storageID)
        guard core.currentStorageId() == storageID,
              let storage = storages.first(where: { $0.id == storageID }),
              let id = core.currentVaultId(), let vault = vaults.first(where: { $0.id == id }) else {
            throw CoreError.Sync(kind: "context_changed", message: "The open storage changed while loading its contents.")
        }
        return VaultModel.Contents(
            page: page, query: query, vaults: vaults, vault: vault,
            storages: storages, storage: storage, syncState: syncState
        )
    }

    static func page(_ core: CoreFacade, query: String, cursor: String?, limit: UInt32) throws -> ItemPage {
        try core.itemsList(
            filter: ItemsFilter(query: query.isEmpty ? nil : query, includeDeleted: true),
            page: Page(limit: limit, cursor: cursor)
        )
    }
}
