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
                // Creating adds to the list, so it sits over the list.
                .toolbar { createMenu }
        } detail: {
            ItemDetailView(
                vault: vault,
                strings: app.strings,
                preferences: app.preferences,
                revealAll: reveal.isHeld
            )
            .toolbar { detailToolbar }
        }
        .sheet(item: editor) { editor in
            ItemEditorView(editor: editor, vault: vault, strings: app.strings)
        }
    }

    private var createMenu: some ToolbarContent {
        ToolbarItem {
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
            .help("\(app.strings("common.create")) (⌘N)")
            .disabled(vault.switching || !vault.contextReady || vault.vaultID == nil)
        }
    }

    /// Item editing stays with the detail pane; locking uses app commands.
    private var detailToolbar: some ToolbarContent {
        ToolbarItem {
            Button {
                Task { await vault.startEditing() }
            } label: {
                Label(app.strings("common.edit"), systemImage: "pencil")
            }
            .help("\(app.strings("common.edit")) (⌘E)")
            .disabled(!vault.canEdit)
        }
    }

    /// Dismissing the sheet from outside the form (lock) discards the draft.
    private var editor: Binding<ItemEditorModel?> {
        Binding(get: { vault.editor }, set: { if $0 == nil { vault.cancelEditing() } })
    }
}

struct VaultSidebar: View {
    @ObservedObject var vault: VaultModel
    let strings: Strings

    /// One selection across both sections: a category clears the folder, a
    /// folder lists it across every live item.
    enum Selection: Hashable {
        case category(String)
        case folder(FolderFilterFfi)
    }

    var body: some View {
        List(selection: selection) {
            ForEach(vault.categories, id: \.id) { category in
                Label(strings(category.labelKey), systemImage: Symbols.category(category.icon))
                    .badge(Int(category.count))
                    // A search counts its matches; a category with none fades.
                    .foregroundStyle(vault.searchMatchCount != nil && category.count == 0 ? .secondary : .primary)
                    .tag(Selection.category(category.id))
            }
            if !vault.folders.tree.isEmpty {
                Section(strings("nav.folders")) {
                    OutlineGroup(vault.folders.tree, id: \.path, children: \.subfolders) { node in
                        Label(node.name, systemImage: "folder")
                            .badge(Int(node.totalCount))
                            .tag(Selection.folder(.path(path: node.path)))
                    }
                    if vault.folders.itemsWithoutFolder > 0 {
                        Label(strings("nav.noFolder"), systemImage: "tray")
                            .badge(Int(vault.folders.itemsWithoutFolder))
                            .tag(Selection.folder(.withoutFolder))
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .disabled(vault.switching || !vault.contextReady)
        .safeAreaInset(edge: .top) {
            VaultContextHeader(vault: vault, strings: strings)
        }
    }

    private var selection: Binding<Selection?> {
        Binding(
            get: {
                vault.folder == .any ? .category(vault.categoryID) : .folder(vault.folder)
            },
            set: { selection in
                switch selection {
                case .category(let id):
                    vault.folder = .any
                    vault.categoryID = id
                case .folder(let folder):
                    vault.categoryID = "all"
                    vault.folder = folder
                case nil:
                    break
                }
            }
        )
    }
}

private extension FolderNodeFfi {
    /// `OutlineGroup` marks leaves by `nil` children, not an empty list.
    var subfolders: [FolderNodeFfi]? {
        children.isEmpty ? nil : children
    }
}
