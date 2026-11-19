import SwiftUI
import ZannCoreKit

/// The create and edit form, as a sheet over the vault so the selection
/// cannot change under an unsaved draft. Every edit goes straight into the
/// zann-ui-core draft, which also validates on save.
struct ItemEditorView: View {
    @ObservedObject var editor: ItemEditorModel
    @ObservedObject var vault: VaultModel
    let strings: Strings
    @EnvironmentObject private var app: AppModel
    @Environment(\.scenePhase) private var scenePhase

    /// Explicit per-field reveals; reset whenever field indices shift.
    @StateObject private var reveal = FieldRevealState()
    @State private var additionalExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            #if os(macOS)
            heading.padding([.horizontal, .top], 24).padding(.bottom, 16)
            #endif
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    #if os(iOS)
                    heading.padding(.top, 20)
                    if let error = editor.error { Text(message(error)).foregroundStyle(.red) }
                    #endif
                    ItemEditorLocation(editor: editor, strings: strings, onSetType: setType)
                    fieldList
                }
                .padding(.horizontal, 24)
                .padding(.bottom, 16)
            }
            #if os(iOS)
            .scrollDismissesKeyboard(.interactively)
            #endif
            Divider()
            footer.padding(16)
        }
        #if os(macOS)
        .frame(minWidth: 640, idealWidth: 700, minHeight: 440, idealHeight: 560)
        #else
        .frame(maxWidth: 760)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        #endif
        .disabled(editor.busy)
        .onChange(of: scenePhase) { if $0 != .active { reveal.reset() } }
        .onDisappear { reveal.reset() }
        .onGeometryChange(for: CGSize.self) { $0.size } action: { _ in reveal.reset() }
        .onChange(of: editor.fields.map { $0.key }) { _ in reveal.reset() }
    }

    private var heading: some View {
        Text(strings(editor.mode == .create ? "create.itemHeader" : "create.itemEditHeader"))
            .font(.title2.bold())
    }

    private var fieldList: some View {
        VStack(alignment: .leading, spacing: 16) {
            fieldRows(editor.mainFieldIndices, labeled: true)
            if let rules = editor.matchRules {
                Picker(strings("fields.match_rules"), selection: Binding(
                    get: { rules.mode },
                    set: { editor.setMatchRules(mode: $0, pattern: rules.pattern) }
                )) {
                    ForEach(ItemEditorModel.matchModes, id: \.mode) { option in
                        Text(strings(option.label)).tag(option.mode)
                    }
                }
                .pickerStyle(.menu)
                if rules.mode == .regex {
                    TextField(strings("autofill.pattern"), text: Binding(
                        get: { rules.pattern },
                        set: { editor.setMatchRules(mode: .regex, pattern: $0) }
                    ))
                }
            }
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
                            .appleTouchTarget()
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
                    revealed: reveal.revealed.contains(index),
                    key: binding(field, index, \.key, editor.setKey),
                    value: binding(field, index, \.value, editor.setValue),
                    kind: binding(field, index, \.kind, editor.setKind),
                    onToggleReveal: { toggleReveal(index) },
                    onRemove: { remove(index) },
                    onGenerated: { value in
                        reveal.reset()
                        editor.setValue(index, value)
                    }
                )
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color.zannFieldBackground)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(Color.zannSeparator)
        )
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 8) {
            #if os(macOS)
            if let error = editor.error {
                Text(message(error))
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            #endif
            ViewThatFits(in: .horizontal) {
                footerButtons.labelStyle(.titleOnly)
                footerButtons.labelStyle(.iconOnly)
            }.frame(maxWidth: .infinity, alignment: .trailing)
        }
    }

    private var footerButtons: some View {
        HStack {
                if editor.busy {
                    ProgressView().controlSize(.small)
                }
                Button { vault.cancelEditing() } label: {
                    Label(strings("common.cancel"), systemImage: "xmark")
                        .appleTouchTarget()
                }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("editor.cancel")
                Button { Task { await vault.saveEditor() } } label: {
                    Label(strings("common.save"), systemImage: "checkmark")
                        .appleTouchTarget()
                }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("editor.save")
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
        reveal.reset()
        additionalExpanded = false
    }

    private func toggleReveal(_ index: Int) {
        reveal.toggle(index, seconds: app.preferences.autoHideRevealSeconds)
    }

    private func remove(_ index: Int) {
        editor.removeField(index)
        reveal.reset()
    }
}
