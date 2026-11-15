import SwiftUI
import ZannCoreKit

struct MobileContextView: View {
    @ObservedObject var vault: VaultModel
    let strings: Strings
    let showItems: () -> Void

    var body: some View {
        List {
            Section {
                VaultContextHeader(vault: vault, strings: strings)
            }
            Section {
                ForEach(vault.categories, id: \.id) { category in
                    Button {
                        vault.folder = .any
                        vault.categoryID = category.id
                        showItems()
                    } label: {
                        HStack {
                            Label(strings(category.labelKey), systemImage: Symbols.category(category.icon))
                            Spacer()
                            Text(String(category.count)).foregroundStyle(.secondary)
                            if vault.folder == .any && vault.categoryID == category.id {
                                Image(systemName: "checkmark").accessibilityHidden(true)
                            }
                        }.frame(minHeight: 44)
                    }
                    .accessibilityIdentifier("category.\(category.id)")
                    .accessibilityAddTraits(vault.folder == .any && vault.categoryID == category.id ? .isSelected : [])
                }
            }
            if !vault.folders.tree.isEmpty {
                Section(strings("nav.folders")) {
                    OutlineGroup(vault.folders.tree, id: \.path, children: \.mobileChildren) { folder in
                        Button {
                            vault.categoryID = "all"
                            vault.folder = .path(path: folder.path)
                            showItems()
                        } label: {
                            Label(folder.name, systemImage: "folder").frame(minHeight: 44)
                        }
                    }
                    if vault.folders.itemsWithoutFolder > 0 {
                        Button {
                            vault.categoryID = "all"
                            vault.folder = .withoutFolder
                            showItems()
                        } label: { Text(strings("nav.noFolder")).appleTouchTarget() }
                    }
                }
            }
            if let error = vault.error { Text(error).foregroundStyle(.red) }
        }
        .listStyle(.sidebar)
        .disabled(vault.switching || !vault.contextReady || vault.editor != nil)
        .navigationTitle(strings("nav.vaults"))
        .accessibilityIdentifier("workspace.context")
    }
}

private extension FolderNodeFfi {
    var mobileChildren: [FolderNodeFfi]? { children.isEmpty ? nil : children }
}
