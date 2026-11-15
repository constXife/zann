import SwiftUI
import ZannCoreKit

struct MobileItemList: View {
    @ObservedObject var vault: VaultModel
    @ObservedObject var navigation: MobileNavigation
    let strings: Strings
    let open: (String) -> Void
    @State private var restoring = true

    var body: some View {
        ScrollViewReader { scroll in
            List(vault.visibleItems, id: \.id) { item in
                Button { open(item.id) } label: {
                    HStack(spacing: 12) {
                        ItemIcon(typeID: item.typeId)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(item.title).foregroundStyle(.primary)
                            if let caption = item.caption {
                                Text(caption).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        Spacer(minLength: 0)
                        if item.id == vault.selectedItemID {
                            Image(systemName: "checkmark").accessibilityHidden(true)
                        }
                    }.frame(minHeight: 44)
                }
                .id(item.id)
                .accessibilityIdentifier("item.\(item.title)")
                .accessibilityAddTraits(item.id == vault.selectedItemID ? .isSelected : [])
                .background(GeometryReader { row in
                    Color.clear.preference(key: VisibleItemFrames.self,
                        value: [item.id: row.frame(in: .named("mobile.items"))])
                })
                .onAppear { vault.itemAppeared(item.id) }
            }
            .coordinateSpace(name: "mobile.items")
            .onPreferenceChange(VisibleItemFrames.self) { frames in
                guard !restoring else { return }
                if let first = frames.filter({ $0.value.maxY > 0 }).min(by: { $0.value.minY < $1.value.minY }) {
                    navigation.listAnchor = first.key
                }
            }
            .task {
                let anchor = navigation.listAnchor
                await Task.yield()
                if let anchor { scroll.scrollTo(anchor, anchor: .top) }
                restoring = false
            }
        }
        .overlay { emptyState }
        .disabled(vault.switching || !vault.contextReady)
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        .searchable(text: $vault.query, placement: .navigationBarDrawer(displayMode: .always), prompt: strings("items.searchPlaceholder"))
        .scrollDismissesKeyboard(.interactively)
        .accessibilityIdentifier("workspace.items")
    }

    @ViewBuilder private var emptyState: some View {
        if vault.visibleItems.isEmpty {
            VStack(spacing: 12) {
                if let error = vault.syncError, vault.awaitingFirstSync, !vault.syncing {
                    Text(error).foregroundStyle(.secondary)
                    Button { Task { await vault.sync() } } label: { Text(strings("common.retry")).appleTouchTarget() }
                } else if vault.awaitingFirstSync {
                    ProgressView(strings("sync.firstSyncTitle"))
                } else if vault.searching || vault.switching {
                    ProgressView()
                } else if vault.searchMatchCount != nil {
                    Text(strings("items.noSearchResults")).foregroundStyle(.secondary)
                    Button { vault.query = "" } label: { Text(strings("items.clearSearch")).appleTouchTarget() }
                } else {
                    Text(strings("workspace.emptyBody")).foregroundStyle(.secondary)
                    if let action = vault.categories.first(where: { $0.id == vault.categoryID })?.createAction {
                        Button { vault.startCreating(typeID: action.typeId) } label: { Text(strings(action.labelKey)).appleTouchTarget() }
                    }
                }
            }.multilineTextAlignment(.center).padding(24)
        }
    }

    private var title: String {
        switch vault.folder {
        case .path(let path): return path
        case .withoutFolder: return strings("nav.noFolder")
        case .any: return vault.categories.first(where: { $0.id == vault.categoryID }).map { strings($0.labelKey) } ?? "Zann"
        }
    }
}

private struct VisibleItemFrames: PreferenceKey {
    static var defaultValue: [String: CGRect] = [:]
    static func reduce(value: inout [String: CGRect], nextValue: () -> [String: CGRect]) {
        value.merge(nextValue(), uniquingKeysWith: { _, new in new })
    }
}
