import SwiftUI
import ZannCoreKit

/// Only location/type controls; the shared Rust draft still owns validation.
struct ItemEditorLocation: View {
    @ObservedObject var editor: ItemEditorModel
    let strings: Strings
    let onSetType: (String) -> Void

    var body: some View {
        #if os(iOS)
        VStack(alignment: .leading, spacing: 12) {
            Text(strings("create.itemTitle")).foregroundStyle(.secondary)
            TextField(strings("create.itemTitle"), text: $editor.name)
                .accessibilityIdentifier("editor.title")
                .appleTouchTarget()
            Text(strings("create.itemFolder")).foregroundStyle(.secondary)
            TextField(strings("create.itemFolderPlaceholder"), text: $editor.folder)
                .accessibilityLabel(strings("create.itemFolder"))
                .appleTouchTarget()
            Picker(strings("create.itemType"), selection: Binding(get: { editor.typeID }, set: onSetType)) {
                ForEach(ItemEditorModel.typeIDs, id: \.self) { typeID in
                    Text(strings("types.\(typeID)")).tag(typeID)
                }
            }.pickerStyle(.menu).appleTouchTarget()
        }.textFieldStyle(.roundedBorder)
        #else
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 10) {
            GridRow {
                Text(strings("create.itemTitle")).foregroundStyle(.secondary)
                TextField(strings("create.itemTitle"), text: $editor.name)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel(strings("create.itemTitle"))
            }
            GridRow {
                Text(strings("create.itemFolder")).foregroundStyle(.secondary)
                TextField(strings("create.itemFolderPlaceholder"), text: $editor.folder)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel(strings("create.itemFolder"))
            }
            GridRow {
                Text(strings("create.itemType")).foregroundStyle(.secondary)
                Picker(strings("create.itemType"), selection: Binding(get: { editor.typeID }, set: { onSetType($0) })) {
                    ForEach(ItemEditorModel.typeIDs, id: \.self) { typeID in
                        Label(strings("types.\(typeID)"), systemImage: Symbols.item(typeID))
                            .tag(typeID)
                    }
                }
                .labelsHidden()
                .fixedSize()
            }
        }
        #endif
    }

}
