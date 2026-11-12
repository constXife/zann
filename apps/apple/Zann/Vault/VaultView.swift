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
                .safeAreaInset(edge: .bottom) { SyncStatus(vault: vault, strings: app.strings) }
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
                .help("\(app.strings("common.create")) (⌘N)")
                Button {
                    Task { await vault.startEditing() }
                } label: {
                    Label(app.strings("common.edit"), systemImage: "square.and.pencil")
                }
                .help("\(app.strings("common.edit")) (⌘E)")
                .disabled(vault.detail == nil)
                if vault.canSync {
                    Button {
                        Task { await vault.sync() }
                    } label: {
                        Label(
                            app.strings("settings.accounts.syncNow"),
                            systemImage: vault.syncError == nil
                                ? "arrow.triangle.2.circlepath"
                                : "exclamationmark.arrow.triangle.2.circlepath"
                        )
                    }
                    .help(vault.syncError ?? "\(app.strings("settings.accounts.syncNow")) (⌘R)")
                    .disabled(vault.syncing)
                }
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
    }

    /// Dismissing the sheet from outside the form (lock) discards the draft.
    private var editor: Binding<ItemEditorModel?> {
        Binding(get: { vault.editor }, set: { if $0 == nil { vault.cancelEditing() } })
    }
}

/// Shown only while a sync runs or after one failed.
struct SyncStatus: View {
    @ObservedObject var vault: VaultModel
    let strings: Strings

    var body: some View {
        if vault.syncing {
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text(strings("status.syncing")).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
            .background(.bar)
        } else if let error = vault.syncError {
            VStack(alignment: .leading, spacing: 6) {
                Label(error, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                if let stale = vault.staleServer {
                    ForgetServer(stale: stale, strings: strings)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(8)
            .background(.bar)
        }
    }
}

/// The way out of a server whose identity changed, behind a confirmation
/// that says what stays on this Mac.
private struct ForgetServer: View {
    let stale: VaultModel.StaleServer
    let strings: Strings
    @EnvironmentObject private var app: AppModel
    @State private var confirming = false

    var body: some View {
        Button(strings("settings.accounts.forgetServer")) { confirming = true }
            .disabled(app.busy)
            .alert(
                strings("settings.accounts.forgetServer"),
                isPresented: $confirming
            ) {
                Button(strings("settings.accounts.forgetServer"), role: .destructive) {
                    Task { await app.forgetStaleServer() }
                }
                Button(strings("common.cancel"), role: .cancel) {}
            } message: {
                Text(message)
            }
        // A failed forget keeps the vault open, so its error shows here.
        if let error = app.error {
            Text(error).foregroundStyle(.red).textSelection(.enabled)
        }
    }

    private var message: String {
        let confirm = strings("settings.accounts.forgetServerConfirm", ["server": stale.name])
        guard stale.pendingChanges > 0 else { return confirm }
        let pending = strings(
            "settings.accounts.forgetServerPending", ["count": String(stale.pendingChanges)]
        )
        return "\(confirm)\n\n\(pending)"
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
        .safeAreaInset(edge: .top) {
            if vault.vaults.count > 1 { VaultPicker(vault: vault, strings: strings) }
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

/// Which of the storage's vaults the sidebar and the list show, like
/// COSMIC's vault selector above its categories.
private struct VaultPicker: View {
    @ObservedObject var vault: VaultModel
    let strings: Strings

    var body: some View {
        Picker(strings("nav.vaults"), selection: selection) {
            ForEach(vault.vaults, id: \.id) { summary in
                Label(
                    "\(summary.name) (\(summary.itemCount))",
                    systemImage: Symbols.vault(summary.scope)
                )
                .tag(summary.id)
            }
        }
        .pickerStyle(.menu)
        // Switching drops the open form, so it waits until the form closes.
        .disabled(vault.editor != nil || vault.switching)
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
    }

    private var selection: Binding<String> {
        Binding(
            get: { vault.vaultID },
            set: { id in Task { await vault.selectVault(id) } }
        )
    }
}

private extension FolderNodeFfi {
    /// `OutlineGroup` marks leaves by `nil` children, not an empty list.
    var subfolders: [FolderNodeFfi]? {
        children.isEmpty ? nil : children
    }
}

struct ItemList: View {
    @ObservedObject var vault: VaultModel
    let strings: Strings

    var body: some View {
        List(vault.visibleItems, id: \.id, selection: selection) { item in
            HStack(spacing: 10) {
                ItemIcon(typeID: item.typeId)
                // The title already names the item; the caption says where it lives.
                VStack(alignment: .leading, spacing: 1) {
                    Text(item.title).lineLimit(1)
                    if let folder = folderOf(path: item.path) {
                        Text(folder)
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
