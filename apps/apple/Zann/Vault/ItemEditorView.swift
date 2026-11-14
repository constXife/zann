import SwiftUI
import ZannCoreKit

/// The create and edit form, as a sheet over the vault so the selection
/// cannot change under an unsaved draft. Every edit goes straight into the
/// zann-ui-core draft, which also validates on save.
struct ItemEditorView: View {
    @ObservedObject var editor: ItemEditorModel
    @ObservedObject var vault: VaultModel
    let strings: Strings

    /// Explicit per-field reveals; reset whenever field indices shift.
    @State private var revealed: Set<Int> = []
    @State private var additionalExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(strings(editor.mode == .create ? "create.itemHeader" : "create.itemEditHeader"))
                .font(.title2.bold())
                .padding([.horizontal, .top], 24)
                .padding(.bottom, 16)
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    location
                    fieldList
                }
                .padding(.horizontal, 24)
                .padding(.bottom, 16)
            }
            Divider()
            footer.padding(16)
        }
        .frame(minWidth: 640, idealWidth: 700, minHeight: 440, idealHeight: 560)
        .disabled(editor.busy)
    }

    private var location: some View {
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
                Picker(strings("create.itemType"), selection: Binding(get: { editor.typeID }, set: { setType($0) })) {
                    ForEach(ItemEditorModel.typeIDs, id: \.self) { typeID in
                        Label(strings("types.\(typeID)"), systemImage: Symbols.item(typeID))
                            .tag(typeID)
                    }
                }
                .labelsHidden()
                .fixedSize()
            }
        }
    }

    private var fieldList: some View {
        VStack(alignment: .leading, spacing: 16) {
            fieldRows(editor.mainFieldIndices, labeled: true)
            DisclosureGroup(isExpanded: $additionalExpanded) {
                VStack(alignment: .leading, spacing: 8) {
                    fieldRows(editor.additionalFieldIndices, labeled: false)
                    Menu {
                        ForEach(editor.missingMainFields, id: \.key) { definition in
                            Button(strings(definition.label)) { editor.addField(definition) }
                        }
                        Button(strings("create.customFields")) { editor.addField() }
                    } label: {
                        Label(strings("create.addField"), systemImage: "plus")
                    }
                    .fixedSize()
                }
                .padding(.top, 8)
            } label: {
                Text(strings("create.additionalFields"))
            }
        }
    }

    private func fieldRows(_ indices: [Int], labeled: Bool) -> some View {
        VStack(spacing: 0) {
            ForEach(indices, id: \.self) { index in
                let field = editor.fields[index]
                if index != indices.first { Divider().padding(.leading, 12) }
                FieldEditorRow(
                    field: field,
                    label: labeled ? editor.label(for: field.key).map { strings($0) } : nil,
                    strings: strings,
                    revealed: revealed.contains(index),
                    key: binding(field, index, \.key, editor.setKey),
                    value: binding(field, index, \.value, editor.setValue),
                    kind: binding(field, index, \.kind, editor.setKind),
                    onToggleReveal: { toggleReveal(index) },
                    onRemove: { remove(index) }
                )
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(Color(nsColor: .separatorColor))
        )
    }

    private var footer: some View {
        HStack {
            if let error = editor.error {
                Text(message(error))
                    .foregroundStyle(.red)
                    .lineLimit(2)
            }
            Spacer()
            if editor.busy {
                ProgressView().controlSize(.small)
            }
            Button(strings("common.cancel")) { vault.cancelEditing() }
                .keyboardShortcut(.cancelAction)
            Button(strings("common.save")) { Task { await vault.saveEditor() } }
                .keyboardShortcut(.defaultAction)
        }
    }

    private func message(_ error: ItemEditorModel.EditorError) -> String {
        switch error {
        case .translated(let key): return strings(key)
        case .message(let message): return message
        }
    }

    /// Reads the rendered row, so a binding outliving a removed row never
    /// indexes past the fields; edits go to the draft, which republishes them.
    private func binding<T>(
        _ field: DraftFieldFfi,
        _ index: Int,
        _ read: KeyPath<DraftFieldFfi, T>,
        _ write: @escaping (Int, T) -> Void
    ) -> Binding<T> {
        Binding(
            get: { field[keyPath: read] },
            set: { write(index, $0) }
        )
    }

    private func setType(_ typeID: String) {
        editor.setType(typeID)
        revealed = []
        additionalExpanded = false
    }

    private func toggleReveal(_ index: Int) {
        if revealed.remove(index) == nil {
            revealed.insert(index)
        }
    }

    private func remove(_ index: Int) {
        editor.removeField(index)
        revealed = []
    }
}
