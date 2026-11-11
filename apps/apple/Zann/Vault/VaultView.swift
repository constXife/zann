import SwiftUI
import ZannCoreKit

/// Vault home: navigation sidebar -> items list -> item detail, the region
/// order docs/ux/Layout-Responsive-Spec.md requires of every desktop client.
/// Column widths follow COSMIC's `layout` module.
struct VaultView: View {
    @ObservedObject var vault: VaultModel
    @EnvironmentObject private var app: AppModel
    @StateObject private var reveal = RevealModifier()

    var body: some View {
        NavigationSplitView {
            VaultSidebar(vault: vault, strings: app.strings)
                .navigationSplitViewColumnWidth(min: 180, ideal: 220, max: 300)
        } content: {
            ItemList(vault: vault, strings: app.strings)
                .navigationSplitViewColumnWidth(min: 320, ideal: 400, max: 560)
        } detail: {
            ItemDetailView(
                vault: vault,
                strings: app.strings,
                preferences: app.preferences,
                revealAll: reveal.isHeld
            )
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    Task { await app.lock() }
                } label: {
                    Label(app.strings("common.lock"), systemImage: "lock")
                }
                .help("\(app.strings("common.lock")) (⌘L)")
            }
        }
        .frame(minWidth: 900, minHeight: 520)
    }
}

struct VaultSidebar: View {
    @ObservedObject var vault: VaultModel
    let strings: Strings

    var body: some View {
        List(selection: selection) {
            ForEach(vault.categories, id: \.id) { category in
                Label(strings(category.labelKey), systemImage: Symbols.category(category.icon))
                    .badge(Int(category.count))
                    .tag(Optional(category.id))
            }
        }
        .listStyle(.sidebar)
    }

    private var selection: Binding<String?> {
        Binding(
            get: { vault.categoryID },
            set: { if let id = $0 { vault.categoryID = id } }
        )
    }
}

struct ItemList: View {
    @ObservedObject var vault: VaultModel
    let strings: Strings

    var body: some View {
        List(vault.visibleItems, id: \.id, selection: selection) { item in
            HStack(spacing: 10) {
                ItemIcon(typeID: item.typeId)
                VStack(alignment: .leading, spacing: 1) {
                    Text(item.title).lineLimit(1)
                    if !item.path.isEmpty {
                        Text(item.path)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
            }
            .padding(.vertical, 3)
        }
        .overlay {
            if vault.visibleItems.isEmpty {
                Text(strings("items.noItems"))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(24)
            }
        }
        .navigationTitle(categoryTitle)
        .searchable(text: $vault.query, prompt: strings("items.searchPlaceholder"))
    }

    private var categoryTitle: String {
        vault.categories.first { $0.id == vault.categoryID }.map { strings($0.labelKey) } ?? ""
    }

    private var selection: Binding<String?> {
        Binding(get: { vault.selectedItemID }, set: { vault.select($0) })
    }
}
