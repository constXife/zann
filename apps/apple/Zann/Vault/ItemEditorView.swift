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
                Text(strings("create.itemPath")).foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 4) {
                    TextField(
                        "Work/GitHub",
                        text: Binding(get: { editor.path }, set: { editor.setPath($0) })
                    )
                    .textFieldStyle(.roundedBorder)
                    Text(strings("create.itemPathHint"))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            GridRow {
                Text(strings("create.itemType")).foregroundStyle(.secondary)
                Picker("", selection: Binding(get: { editor.typeID }, set: { setType($0) })) {
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
        VStack(alignment: .leading, spacing: 8) {
            Text(strings("create.customFields")).font(.headline)
            if editor.fields.isEmpty {
                Text(strings("create.noFields")).foregroundStyle(.secondary)
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(editor.fields.enumerated()), id: \.offset) { index, field in
                        if index > 0 {
                            Divider().padding(.leading, 12)
                        }
                        FieldEditorRow(
                            field: field,
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
            Button {
                editor.addField()
            } label: {
                Label(strings("create.addField"), systemImage: "plus")
            }
        }
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

private struct FieldEditorRow: View {
    let field: DraftFieldFfi
    let strings: Strings
    let revealed: Bool
    @Binding var key: String
    @Binding var value: String
    @Binding var kind: FieldKindFfi
    let onToggleReveal: () -> Void
    let onRemove: () -> Void

    var body: some View {
        HStack(alignment: field.multiline && !field.masked ? .top : .center, spacing: 8) {
            TextField(strings("create.fieldKeyPlaceholder"), text: $key)
                .textFieldStyle(.roundedBorder)
                .frame(width: 140)
            valueEditor
            Button(action: onToggleReveal) {
                Image(systemName: revealed ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            .help(strings(revealed ? "create.hideValue" : "create.revealValue"))
            // Same slot on every row so the value columns line up.
            .opacity(field.masked ? 1 : 0)
            .disabled(!field.masked)
            Picker("", selection: $kind) {
                ForEach(ItemEditorModel.kinds, id: \.self) { kind in
                    Text(strings(Self.kindKey(kind))).tag(kind)
                }
            }
            .labelsHidden()
            .frame(width: 130)
            Button(action: onRemove) {
                Image(systemName: "minus.circle")
            }
            .buttonStyle(.borderless)
            .help(strings("create.removeRow"))
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    @ViewBuilder private var valueEditor: some View {
        let placeholder = strings("create.fieldValuePlaceholder")
        if field.masked && !revealed {
            SecureField(placeholder, text: $value)
                .textFieldStyle(.roundedBorder)
                .font(.body.monospaced())
        } else if field.multiline {
            TextEditor(text: $value)
                .font(.body)
                .frame(minHeight: 80, maxHeight: 160)
                .overlay(
                    RoundedRectangle(cornerRadius: 5)
                        .strokeBorder(Color(nsColor: .separatorColor))
                )
        } else {
            TextField(placeholder, text: $value)
                .textFieldStyle(.roundedBorder)
                .font(field.masked ? .body.monospaced() : .body)
        }
    }

    private static func kindKey(_ kind: FieldKindFfi) -> String {
        switch kind {
        case .text: return "create.kindText"
        case .password: return "create.kindPassword"
        case .url: return "create.kindUrl"
        case .otp: return "create.kindOtp"
        case .note: return "create.kindNote"
        }
    }
}
