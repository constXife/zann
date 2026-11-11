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
            ToolbarItemGroup(placement: .primaryAction) {
                Menu {
                    ForEach(ItemEditorModel.typeIDs, id: \.self) { typeID in
                        Button {
                            vault.startCreating(typeID: typeID)
                        } label: {
                            Label(app.strings("types.\(typeID)"), systemImage: Symbols.item(typeID))
                        }
                    }
                } label: {
                    Label(app.strings("common.create"), systemImage: "plus")
                } primaryAction: {
                    vault.startCreating()
                }
                .keyboardShortcut("n", modifiers: .command)
                .help("\(app.strings("common.create")) (⌘N)")
                Button {
                    Task { await vault.startEditing() }
                } label: {
                    Label(app.strings("common.edit"), systemImage: "square.and.pencil")
                }
                .keyboardShortcut("e", modifiers: .command)
                .help("\(app.strings("common.edit")) (⌘E)")
                .disabled(vault.detail == nil)
                Button {
                    Task { await app.lock() }
                } label: {
                    Label(app.strings("common.lock"), systemImage: "lock")
                }
                .help("\(app.strings("common.lock")) (⌘L)")
            }
        }
        .sheet(item: editor) { editor in
            ItemEditorView(editor: editor, vault: vault, strings: app.strings)
        }
        .frame(minWidth: 900, minHeight: 520)
    }

    /// Dismissing the sheet from outside the form (lock) discards the draft.
    private var editor: Binding<ItemEditorModel?> {
        Binding(get: { vault.editor }, set: { if $0 == nil { vault.cancelEditing() } })
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
