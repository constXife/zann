import SwiftUI
import ZannCoreKit

struct ItemList: View {
    @ObservedObject var vault: VaultModel
    let strings: Strings
    @FocusState private var listFocused: Bool

    var body: some View {
        ScrollViewReader { scroll in
            items
                .focused($listFocused)
                .onChange(of: vault.selectedItemID) { id in
                    if let id { scroll.scrollTo(id) }
                }
        }
        .overlay {
            if vault.visibleItems.isEmpty && vault.awaitingFirstSync {
                VStack(spacing: 12) {
                    if let error = vault.syncError, !vault.syncing {
                        Text(strings("status.syncError")).font(.headline)
                        Text(error).foregroundStyle(.secondary)
                        Button(strings("common.retry")) { Task { await vault.sync() } }
                    } else {
                        ProgressView()
                        Text(strings("sync.firstSyncTitle")).font(.headline)
                        Text(strings("sync.firstSyncBody")).foregroundStyle(.secondary)
                    }
                }
                .multilineTextAlignment(.center)
                .padding(24)
            } else if vault.visibleItems.isEmpty && (vault.searching || vault.loadingMore || vault.switching) {
                ProgressView()
            } else if vault.visibleItems.isEmpty {
                VStack(spacing: 12) {
                    Text(strings(hasSearchQuery ? "items.noSearchResults" : "workspace.emptyBody"))
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                    if hasSearchQuery {
                        Button(strings("items.clearSearch")) { vault.query = "" }
                    } else if let action = createAction {
                        Button(strings(action.labelKey)) { vault.startCreating(typeID: action.typeId) }
                            .buttonStyle(.borderedProminent)
                    }
                }
                .padding(24)
            }
        }
        .disabled(vault.switching || !vault.contextReady)
        .navigationTitle(categoryTitle)
        .navigationSubtitle(searchSubtitle)
        .searchable(text: $vault.query, prompt: strings("items.searchPlaceholder"))
        .background(SearchResultNavigation {
            guard !vault.searching, let first = vault.visibleItems.first else { return false }
            vault.select(first.id)
            listFocused = true
            return true
        })
    }

    private var hasSearchQuery: Bool {
        !vault.query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    private var createAction: CategoryCreateActionFfi? {
        vault.categories.first { $0.id == vault.categoryID }?.createAction
    }

    private var items: some View {
        List(vault.visibleItems, id: \.id, selection: selection) { item in
            HStack(spacing: 10) {
                ItemIcon(typeID: item.typeId)
                // The title names the item; the caption says who or where it
                // is for and where it lives.
                VStack(alignment: .leading, spacing: 1) {
                    Text(item.title).lineLimit(1)
                    if let caption = item.caption {
                        Text(caption)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
            }
            .padding(.vertical, 3)
            .tag(item.id)
            // Rows near the end load the next page, so scrolling reaches
            // every item.
            .onAppear { vault.itemAppeared(item.id) }
        }
    }

    /// Says the list shows search matches, not the whole category.
    private var searchSubtitle: String {
        guard let count = vault.searchMatchCount else { return "" }
        return strings("items.searchMatches", ["count": String(count), "query": vault.searchedQuery])
    }

    private var categoryTitle: String {
        switch vault.folder {
        case .path(let path): return path
        case .withoutFolder: return strings("nav.noFolder")
        case .any:
            return vault.categories.first { $0.id == vault.categoryID }
                .map { strings($0.labelKey) } ?? ""
        }
    }

    private var selection: Binding<String?> {
        Binding(get: { vault.selectedItemID }, set: { vault.select($0) })
    }
}
