import Foundation
import ZannCoreKit

/// How many items one `itemsList` call pages in, as COSMIC's `PAGE_LIMIT`.
let itemsPageLimit: UInt32 = 200
/// Scrolling keeps at most this many items loaded, as COSMIC's
/// `ITEM_CACHE_LIMIT`; a search still reaches the whole vault past it.
private let itemCacheLimit = Int(itemsPageLimit) * 5
/// A row this close to the end of the list loads the next page.
private let prefetchRows = 40
/// A category or folder showing fewer rows loads the next page by itself.
private let minVisibleRows = 24
/// The pause after a keystroke before the core searches, as COSMIC's.
private let searchDebounceNanoseconds: UInt64 = 180_000_000

/// The `CoreError.Sync` kind for a server that no longer proves the identity
/// this device pinned.
private let serverIdentityChanged = "server_identity_changed"

/// One unlocked vault: the loaded pages, the sidebar categories, the visible
/// list and the selected item's projected fields. The core searches and
/// pages; categories, filtering and field projection come from zann-ui-core;
/// this type only holds selection and sequences the blocking calls. Dropping
/// it on lock drops every secret it held.
@MainActor
final class VaultModel: ObservableObject {
    typealias Detail = ItemDetailViewFfi

    /// The server that syncs this vault proves a different identity than the
    /// one this device pinned. Retrying cannot help; the way out is to forget
    /// it and connect again, and the confirmation says how many local changes
    /// wait for that.
    struct StaleServer: Equatable {
        let storageID: String
        let name: String
        let pendingChanges: UInt64
    }

    /// The vault on screen is a server's, but no connection syncs it any
    /// more: its server was forgotten, or its sign-in never reached this
    /// Mac's config. Its unsent changes wait until the user connects to
    /// `serverURL` again with the same account, which takes the vault over.
    struct Disconnected: Equatable {
        let serverURL: String?
        let pendingChanges: UInt64
    }

    /// The open vault's first page for `query` with the storage's vaults,
    /// loaded together so the picker and the list never disagree.
    struct Contents {
        let page: ItemPage
        let query: String
        let vaults: [VaultSummaryFfi]
        let vault: VaultSummaryFfi?
        let storages: [StorageSummaryFfi]
        let storage: StorageSummaryFfi?
        let syncState: StorageSyncStateFfi?
        let serverConnected: Bool
    }

    /// The vaults of the storage on screen; the picker shows when there are
    /// several.
    @Published private(set) var vaults: [VaultSummaryFfi] = []
    /// The vault whose items are listed.
    @Published private(set) var vaultID: String?
    @Published private(set) var storageID: String?
    @Published private(set) var storages: [StorageSummaryFfi] = []
    @Published private(set) var contextReady = true
    /// A vault switch is loading.
    @Published private(set) var switching = false
    @Published private(set) var categories: [CategoryViewFfi] = []
    @Published private(set) var folders = FolderTreeFfi(itemsWithoutFolder: 0, tree: [])
    @Published private(set) var visibleItems: [ItemSummary] = []
    @Published private(set) var totalCount: UInt64 = 0
    @Published private(set) var detail: Detail?
    @Published private(set) var detailLoading = false

    var canEdit: Bool { detail != nil && detail?.id == selectedItemID && !switching && contextReady }
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
        didSet { if query != oldValue { queryChanged() } }
    }

    /// The core is searching for a query typed after the list loaded.
    @Published private(set) var searching = false
    /// The next page is loading.
    @Published private(set) var loadingMore = false

    @Published private(set) var selectedItemID: String?
    /// The open create or edit form; at most one at a time.
    @Published private(set) var editor: ItemEditorModel?
    /// Whether a server holds this vault's storage, so syncing means something.
    @Published private(set) var canSync: Bool
    /// The selected server has not committed its first cache checkpoint yet.
    var awaitingFirstSync: Bool {
        guard canSync else { return false }
        if storageID == nil { return true }
        return !vaults.isEmpty && syncState?.link == .connected &&
            syncState?.lastSyncedAt == nil && (running == nil || syncing)
    }
    @Published private(set) var syncingStorageID: String?
    /// Progress belongs to its server, even after navigation moves elsewhere.
    var syncing: Bool { running != nil && syncingStorageID == storageID }
    /// Why the last sync failed; the vault stays usable offline.
    @Published private(set) var syncError: String?
    /// Set while the last sync was refused for a changed server identity.
    @Published private(set) var staleServer: StaleServer?
    /// Set while the last sync found the vault's server connection gone.
    @Published private(set) var disconnected: Disconnected?
    /// What the sync indicator knows about the open storage.
    @Published private(set) var syncState: StorageSyncStateFfi?

    /// The sidebar's sync indicator, as zann-ui-core decides it.
    var indicator: SyncIndicatorFfi? {
        guard syncState != nil || canSync else { return nil }
        return syncIndicator(
            input: SyncStatusInputFfi(
                link: syncState?.link ?? .connected,
                serverUrl: syncState?.serverUrl,
                pendingChanges: syncState?.pendingChanges ?? 0,
                syncing: syncing,
                failed: syncError != nil
            )
        )
    }

    private let detailLoader: ItemDetailLoader
    private let core: CoreFacade
    private let strings: Strings
    /// The core decides when to sync and admits one sync at a time, manual
    /// or automatic; this type only runs the timer and the sync.
    private let schedule = AutoSyncScheduleFfi()
    private var autoSync: Task<Void, Never>?
    /// The sync the schedule admitted, until it ends.
    @Published private var running: Task<Void, Never>?
    private var syncRunID: UUID?
    private var syncRelay: SyncCommitRelay?
    /// Invalidates UI reads across vault/storage switches, including A → B → A.
    private var contextGeneration = 0
    /// A completed pull may need a fresh page after a local switch finishes.
    private struct SyncRefresh { let storageID: String? }
    private var syncRefreshContext: SyncRefresh?
    private var refreshingSync = false
    /// The loaded pages of the list for `appliedQuery`.
    private var items: [ItemSummary] = []
    private var nextCursor: String?
    /// The trimmed query whose results `items` holds. While a newer one waits
    /// for the core, the loaded items narrow locally.
    private var appliedQuery = ""
    /// Bumped whenever `items` is replaced, so a page loaded for an older list
    /// is dropped.
    private var listGeneration = 0
    private var search: Task<Void, Never>?
    private var counts: ItemCountsFfi
    /// Shared vaults show the infrastructure categories.
    private var scope: VaultScopeFfi?
    /// Bumped on every selection so a slow load cannot show a previous item.
    private var selection = 0
    var detailSelectionGeneration: Int { selection }
    /// Cached replicas open immediately; the core selects a first synced catalog.
    init(
        core: CoreFacade, contents: Contents, strings: Strings
    ) {
        detailLoader = ItemDetailLoader(core: core)
        self.core = core
        self.strings = strings
        counts = contents.page.counts
        vaultID = contents.vault?.id
        storageID = contents.storage?.id
        scope = contents.vault?.scope
        categoryID = "all"
        canSync = contents.syncState != nil || contents.serverConnected
        schedule.unlocked(synced: false)
        apply(contents)
        Task { await refreshSyncState() }
    }

    /// Reads the open storage's sync state again; a failed read keeps the
    /// last one rather than hiding the indicator.
    func refreshSyncState() async {
        let core = core
        guard let wanted = storageID else { return }
        let generation = contextGeneration
        let result = await Task.detached(priority: .userInitiated) {
            Result { try core.storageSyncState(storageId: wanted) }
        }.value
        guard wanted == storageID, generation == contextGeneration, !switching else { return }
        if case .success(let state) = result { applySyncState(state) }
    }

    /// Syncs whenever the core's schedule says so until `stopAutoSync`. A tick
    /// that finds nothing due costs one call into the core.
    func startAutoSync() {
        guard autoSync == nil else { return }
        autoSync = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                if !self.switching, self.contextReady, let ticket = self.schedule.takeDue() {
                    await self.start(ticket).value
                }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    /// The vault is locking: nothing more is due, and a sync still running
    /// (which the core's lock cancels) schedules nothing.
    func stopAutoSync() {
        contextGeneration += 1
        syncRunID = nil
        syncRelay?.cancel()
        detailLoader.cancel()
        detailLoading = false
        autoSync?.cancel()
        autoSync = nil
        schedule.locked()
    }

    /// Syncs now, or waits for the sync already running.
    func sync() async {
        guard !switching, contextReady else { return }
        let wanted = storageID
        if let running, syncingStorageID != wanted {
            await running.value
            guard wanted == storageID, !switching, contextReady else { return }
        }
        if let ticket = schedule.takeNow() {
            start(ticket)
        }
        await running?.value
    }

    @discardableResult
    private func start(_ ticket: AutoSyncTicketFfi) -> Task<Void, Never> {
        let storage = storageID
        syncingStorageID = storage
        let task = Task { await self.run(ticket, storage: storage) }
        running = task
        return task
    }

    private enum Synced {
        case noServer
        case completed(changed: Bool)
        case identityChanged(StaleServer)
        case disconnected(Disconnected)
    }

    /// Pushes local changes and pulls the server's, then reloads the list on
    /// screen if anything changed; the core picks the server and the vault to
    /// show. A Mac that never signed in to a server has nothing to sync.
    private func run(_ ticket: AutoSyncTicketFfi, storage wantedStorage: String?) async {
        let runID = UUID()
        syncRunID = runID
        let bootstrapGeneration = contextGeneration
        let relay = SyncCommitRelay { [weak self] update in
            guard let self, self.syncRunID == runID else { return }
            if self.syncingStorageID == nil { self.syncingStorageID = update.storageId }
            guard self.storageID == update.storageId ||
                (self.storageID == nil && self.contextGeneration == bootstrapGeneration) else { return }
            self.syncRefreshContext = SyncRefresh(storageID: self.storageID)
            await self.refreshSyncedContents(reloadDetail: false)
        }
        syncRelay = relay
        defer {
            relay.cancel()
            syncRelay = nil
            syncRunID = nil
            running = nil
            syncingStorageID = nil
            schedule.finished(ticket: ticket)
        }
        let core = core
        let result = await Task.detached(priority: .userInitiated) {
            Result { () -> Synced in
                if let wantedStorage {
                    let state = try core.storageSyncState(storageId: wantedStorage)
                    if state.link == .disconnected {
                        return .disconnected(Disconnected(serverURL: state.serverUrl, pendingChanges: state.pendingChanges))
                    }
                } else if try !core.appStatus().serverConnected { return .noServer }
                let outcome: SyncOutcomeFfi
                do {
                    outcome = try core.remoteSync(storageId: wantedStorage, progress: relay)
                } catch let failure as CoreError {
                    guard case .Sync(serverIdentityChanged, _) = failure,
                          let wantedStorage, let stale = try Self.staleServer(core, storageID: wantedStorage)
                    else { throw failure }
                    return .identityChanged(stale)
                }
                return .completed(changed: outcome.changesCommitted > 0)
            }
        }.value
        await relay.finish()
        guard syncRunID == runID, syncingStorageID == storageID else { return }
        switch result {
        case .success(.completed(let changed)):
            succeeded()
            if changed || wantedStorage == nil || vaultID == nil {
                syncRefreshContext = SyncRefresh(storageID: storageID)
                await refreshSyncedContents()
            }
        case .success(.noServer):
            canSync = false
            staleServer = nil
            disconnected = nil
        case .success(.identityChanged(let stale)):
            canSync = true
            syncError = strings("errors.\(serverIdentityChanged)")
            staleServer = stale
            disconnected = nil
        case .success(.disconnected(let gone)):
            canSync = true
            syncError = gone.pendingChanges == 0
                ? strings("errors.server_disconnected")
                : strings(
                    "errors.server_disconnected_pending", ["count": String(gone.pendingChanges)]
                )
            staleServer = nil
            disconnected = gone
        case .failure(let failure):
            canSync = true
            syncError = strings.message(for: failure)
            staleServer = nil
            disconnected = nil
        }
        await refreshSyncState()
    }

    /// Reload the context on screen, never the vault a sync started from.
    /// If navigation supersedes this read, its completion drains the refresh.
    private func refreshSyncedContents(reloadDetail: Bool = true) async {
        guard !refreshingSync, let refresh = syncRefreshContext, !switching else { return }
        refreshingSync = true
        defer { refreshingSync = false }
        let wanted = refresh.storageID
        guard wanted == storageID, contextReady else {
            syncRefreshContext = nil
            return
        }
        let generation = contextGeneration
        let revision = listGeneration
        let core = core
        let shown = trimmedQuery
        let loaded = items.count
        let result = await Task.detached(priority: .userInitiated) {
            Result { try VaultContextLoader.load(core, query: shown, keeping: loaded) }
        }.value
        guard generation == contextGeneration, !switching else { return }
        syncRefreshContext = nil
        switch result {
        case .success(let contents):
            if revision == listGeneration, shown == trimmedQuery {
                apply(contents)
                if reloadDetail, let selectedItemID { loadDetail(selectedItemID) }
            } else {
                // Search/pagination owns the newer list. Its revision must not
                // prevent the first committed server/vault context appearing.
                applyContext(contents)
                categories = scope.map { categoryViews(counts: counts, scope: $0) } ?? []
            }
        case .failure(let failure): syncError = strings.message(for: failure)
        }
    }

    private func succeeded() {
        canSync = true
        syncError = nil
        staleServer = nil
        disconnected = nil
    }

    /// The vault on screen and what forgetting its server leaves behind, or
    /// `nil` when no connection syncs it: then nothing here can be forgotten
    /// and the refusal stays a plain error. Selection is explicit, so this
    /// always describes the storage currently on screen.
    private nonisolated static func staleServer(_ core: CoreFacade, storageID: String) throws -> StaleServer? {
        guard try core.storageSyncState(storageId: storageID).link == .connected else { return nil }
        guard let storage = try core.listStorages().first(where: { $0.id == storageID }) else {
            throw CoreError.InvalidArgument("the vault on screen is not a known storage")
        }
        return StaleServer(
            storageID: storageID,
            name: storage.name,
            pendingChanges: try core.pendingChangeCount(storageId: storageID)
        )
    }

    /// The first page of the current vault and the storage's vaults.
    nonisolated static func load(_ core: CoreFacade) throws -> Contents {
        try VaultContextLoader.load(core, query: "", keeping: 0)
    }

    /// Opens another vault of this storage with nothing filtered or
    /// selected. If its items cannot load, the core goes back to the vault
    /// on screen, so the picker and the list keep agreeing.
    func selectVault(_ id: String) async {
        guard id != vaultID, editor == nil, !switching, contextReady else { return }
        contextGeneration += 1
        switching = true
        listGeneration += 1
        loadingMore = false
        search?.cancel()
        search = nil
        searching = false
        select(nil)
        defer {
            switching = false
            if contextReady { queryChanged() }
            Task { await refreshSyncedContents() }
        }
        let core = core
        let result = await Task.detached(priority: .userInitiated) {
            Result { () -> Contents in
                let previous = core.currentVaultId()
                _ = try core.setCurrentVault(id: id)
                do {
                    return try Self.load(core)
                } catch {
                    if let previous { _ = try core.setCurrentVault(id: previous) }
                    throw error
                }
            }
        }.value
        switch result {
        case .success(let contents):
            error = nil
            select(nil)
            query = ""
            folder = .any
            categoryID = "all"
            apply(contents)
        case .failure(let failure):
            error = describe(failure)
        }
    }

    /// Switches only registered storage contexts. A refused switch keeps the
    /// current list; a committed context whose reads fail never shows old data.
    func selectStorage(_ id: String) async {
        guard id != storageID, editor == nil, !switching else { return }
        guard let target = storages.first(where: { $0.id == id }) else { return }
        contextGeneration += 1
        switching = true
        listGeneration += 1
        loadingMore = false
        search?.cancel()
        search = nil
        searching = false
        select(nil)
        defer {
            switching = false
            if contextReady { queryChanged() }
            Task { await refreshSyncedContents() }
        }
        let core = core
        let outcome = await Task.detached(priority: .userInitiated) {
            VaultContextLoader.select(core, storage: target)
        }.value
        switch outcome {
        case .refused(let failure):
            error = strings.message(for: failure)
        case .loaded(let contents):
            query = ""
            folder = .any
            categoryID = "all"
            syncError = nil
            staleServer = nil
            disconnected = nil
            apply(contents)
            error = nil
        case .unreadable(let failure):
            query = ""
            folder = .any
            categoryID = "all"
            canSync = false
            staleServer = nil
            disconnected = nil
            nextCursor = nil
            loadingMore = false
            totalCount = 0
            appliedQuery = ""
            storageID = target.id
            vaultID = nil
            vaults = []
            items = []
            visibleItems = []
            categories = []
            folders = FolderTreeFfi(itemsWithoutFolder: 0, tree: [])
            syncState = nil
            syncError = nil
            contextReady = false
            error = strings.message(for: failure)
        }
    }

    func select(_ id: String?) {
        guard !switching || id == nil, contextReady || id == nil, id != selectedItemID else { return }
        show(id)
    }

    /// A new item of `typeID`, or of the type zann-ui-core picks for the
    /// selected category.
    func startCreating(typeID: String? = nil) {
        guard editor == nil, !switching, contextReady, vaultID != nil else { return }
        let type = typeID ?? createTypeForCategory(categoryId: categoryID)
        open { try ItemEditorModel.create(typeID: type) }
    }

    func startEditing() async {
        guard editor == nil, canEdit, let id = detail?.id else { return }
        let core = core
        let wanted = storageID
        let token = selection
        let result = await Task.detached(priority: .userInitiated) {
            Result { try core.itemGet(id: id) }
        }.value
        guard wanted == storageID, token == selection, !switching else { return }
        open { try ItemEditorModel.edit(try result.get()) }
    }

    func cancelEditing() {
        editor = nil
    }

    /// Saves the open form, then reloads the list and shows the saved item.
    func saveEditor() async {
        guard let editor, let item = await editor.save(with: core) else { return }
        self.editor = nil
        schedule.localChange()
        Task { await refreshSyncState() }
        guard await reload(query: trimmedQuery) else { return }
        // A saved item can fall outside the current category, folder or
        // search; the newest change heads the unfiltered first page.
        if !visibleItems.contains(where: { $0.id == item.id }) {
            if !appliedQuery.isEmpty {
                guard await reload(query: "") else { return }
            }
            query = ""
            folder = .any
            categoryID = "all"
        }
        show(item.id)
    }

    /// Replaces the list with its start for `query`, as many items as are
    /// loaded now; a failure shows its error and keeps the list.
    private func reload(query: String) async -> Bool {
        let core = core
        let loaded = items.count
        let wanted = storageID
        let generation = contextGeneration
        let result = await Task.detached(priority: .userInitiated) {
            Result { try VaultContextLoader.load(core, query: query, keeping: loaded) }
        }.value
        guard wanted == storageID, generation == contextGeneration, !switching else { return false }
        switch result {
        case .success(let contents):
            apply(contents)
            return true
        case .failure(let failure):
            error = describe(failure)
            return false
        }
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
        error = nil
        selection += 1
        if let id {
            loadDetail(id)
        } else {
            detailLoader.cancel()
            detail = nil
            detailLoading = false
        }
    }

    private func loadDetail(_ id: String) {
        detailLoading = true
        detailLoader.load(id) { [weak self] result in
            guard let self else { return }
            self.detailLoading = false
            switch result {
            case .success(let detail): self.detail = detail
            case .failure(let failure):
                self.detail = nil
                self.error = describe(failure)
            }
        }
    }

    private func applySyncState(_ state: StorageSyncStateFfi) {
        syncState = state
        canSync = true
        disconnected = state.link == .disconnected
            ? Disconnected(serverURL: state.serverUrl, pendingChanges: state.pendingChanges) : nil
    }

    /// Shows `contents` in place of everything loaded. A search started for
    /// the list it replaces is dropped, since the core may have switched
    /// vaults since; one for the query typed now starts again.
    private func applyContext(_ contents: Contents) {
        vaults = contents.vaults
        vaultID = contents.vault?.id
        storages = contents.storages
        storageID = contents.storage?.id
        syncState = contents.syncState
        canSync = contents.syncState != nil || contents.serverConnected
        if let state = contents.syncState { applySyncState(state) }
        contextReady = true
        scope = contents.vault?.scope
    }

    private func apply(_ contents: Contents) {
        applyContext(contents)
        search?.cancel()
        search = nil
        searching = false
        replace(with: contents.page, query: contents.query)
        if trimmedQuery != appliedQuery { searchFor(trimmedQuery) }
    }

    /// Starts the list over at `page`, the first one for `query`.
    private func replace(with page: ItemPage, query: String) {
        listGeneration += 1
        loadingMore = false
        appliedQuery = query
        items = page.items
        take(page)
    }

    /// Takes the cursor and the counts of the page just added to `items`.
    /// Categories count the whole vault, or the matches of a search, as the
    /// core reports them; folders come from the loaded pages, and a search
    /// leaves them as browsing found them.
    private func take(_ page: ItemPage) {
        nextCursor = page.nextCursor
        counts = page.counts
        totalCount = page.totalCount
        categories = scope.map { categoryViews(counts: counts, scope: $0) } ?? []
        if appliedQuery.isEmpty { folders = buildFolderTree(items: items) }
        refreshVisible()
    }

    /// The query the list now answers.
    var searchedQuery: String { appliedQuery }

    /// How many items match the search in the open category or folder; nil
    /// while browsing, or while a newer query is on its way to the core.
    var searchMatchCount: Int? {
        guard !appliedQuery.isEmpty, trimmedQuery == appliedQuery, !searching else { return nil }
        if folder == .any {
            return categories.first { $0.id == categoryID }.map { Int($0.count) }
        }
        // The core counts categories, not folders, so a folder counts the
        // loaded matches, and only once every one is loaded.
        return nextCursor == nil ? visibleItems.count : nil
    }

    private var trimmedQuery: String {
        query.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// A query the loaded items do not answer goes to the core after a pause;
    /// one they do drops any search still waiting.
    private func queryChanged() {
        guard !switching, contextReady else { return }
        if trimmedQuery == appliedQuery {
            search?.cancel()
            search = nil
            searching = false
        } else {
            searchFor(trimmedQuery)
        }
        refreshVisible()
    }

    /// Replaces the list with the core's first page for `wanted`, unless the
    /// query changes again first. Clearing the query reloads at once.
    private func searchFor(_ wanted: String) {
        search?.cancel()
        searching = true
        let delay: UInt64 = wanted.isEmpty ? 0 : searchDebounceNanoseconds
        let core = core
        search = Task { [weak self] in
            if delay > 0 { try? await Task.sleep(nanoseconds: delay) }
            guard !Task.isCancelled else { return }
            let result = await Task.detached(priority: .userInitiated) {
                Result { try VaultContextLoader.page(core, query: wanted, cursor: nil, limit: itemsPageLimit) }
            }.value
            guard let self, !Task.isCancelled else { return }
            self.search = nil
            self.searching = false
            switch result {
            case .success(let page): self.replace(with: page, query: wanted)
            case .failure(let failure): self.error = describe(failure)
            }
        }
    }

    /// The list shows `id`; near the end of what is loaded, the next page
    /// starts loading.
    func itemAppeared(_ id: String) {
        guard visibleItems.suffix(prefetchRows).contains(where: { $0.id == id }) else { return }
        loadMore()
    }

    /// Appends the next page of the list on screen, up to `itemCacheLimit`
    /// items. A page that lands after the list was replaced is dropped.
    private func loadMore() {
        guard !switching, contextReady, let cursor = nextCursor, !loadingMore, !searching, items.count < itemCacheLimit else {
            return
        }
        loadingMore = true
        let generation = listGeneration
        let query = appliedQuery
        let core = core
        Task { [weak self] in
            let result = await Task.detached(priority: .userInitiated) {
                Result { try VaultContextLoader.page(core, query: query, cursor: cursor, limit: itemsPageLimit) }
            }.value
            guard let self, generation == self.listGeneration else { return }
            self.loadingMore = false
            switch result {
            case .success(let page):
                self.items.append(contentsOf: page.items.prefix(itemCacheLimit - self.items.count))
                self.take(page)
            case .failure(let failure):
                self.error = describe(failure)
            }
        }
    }

    private func refreshVisible() {
        // The core's matches already answer the applied query; a newer one
        // narrows them until the core answers it.
        let narrowing = trimmedQuery == appliedQuery ? "" : query
        let filter = ItemFilterFfi(categoryId: categoryID, folder: folder, query: narrowing)
        visibleItems = filterItems(items: items, filter: filter).map { items[Int($0)] }
        if let selectedItemID, !visibleItems.contains(where: { $0.id == selectedItemID }) {
            select(nil)
        }
        // A category or folder whose items sit further down the vault fills
        // the list without waiting for a scroll.
        if visibleItems.count < minVisibleRows { loadMore() }
    }

}
