import SwiftUI
import ZannCoreKit

struct FieldEditorRow: View {
    let field: DraftFieldFfi
    /// A schema label makes this a standard field; custom fields expose key and kind.
    let label: String?
    let strings: Strings
    let revealed: Bool
    @Binding var key: String
    @Binding var value: String
    @Binding var kind: FieldKindFfi
    let onToggleReveal: () -> Void
    let onRemove: () -> Void
    let onGenerated: (String) -> Void
    @State private var generatorOpen = false

    var body: some View {
        #if os(iOS)
        VStack(alignment: .leading, spacing: 8) {
            if let label {
                Text(label).foregroundStyle(.secondary)
            } else {
                HStack {
                    TextField(strings("create.fieldKeyPlaceholder"), text: $key)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .accessibilityLabel(strings("create.keyLabel"))
                    Button(action: onRemove) { Image(systemName: "minus.circle").appleTouchTarget() }
                        .accessibilityLabel(strings("create.removeRow"))
                }
            }
            HStack {
                valueEditor
                    .accessibilityLabel(label ?? strings("create.valueLabel"))
                    .accessibilityIdentifier("editor.value.\(field.key)")
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .appleTouchTarget()
                if field.masked {
                    Button(action: onToggleReveal) {
                        Image(systemName: revealed ? "eye.slash" : "eye").appleTouchTarget()
                    }
                    .accessibilityLabel(strings(revealed ? "create.hideValue" : "create.revealValue"))
                    .accessibilityIdentifier("editor.reveal.\(field.key)")
                }
            }
            if label == nil {
                Picker(strings("create.fieldType"), selection: $kind) {
                    ForEach(ItemEditorModel.kinds, id: \.self) { kind in
                        Text(strings(Self.kindKey(kind))).tag(kind)
                    }
                }.pickerStyle(.menu)
            }
        }
        .textFieldStyle(.roundedBorder)
        .padding(12)
        #else
        HStack(alignment: field.multiline && !field.masked ? .top : .center, spacing: 8) {
            if let label {
                Text(label)
                    .foregroundStyle(.secondary)
                    .frame(width: 120, alignment: .leading)
            } else {
                TextField(strings("create.fieldKeyPlaceholder"), text: $key)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 140)
                    .accessibilityLabel(strings("create.keyLabel"))
            }
            valueEditor
                .accessibilityLabel(label ?? strings("create.valueLabel"))
            Button(action: onToggleReveal) {
                Image(systemName: revealed ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            .help(strings(revealed ? "create.hideValue" : "create.revealValue"))
            // Same slot on every row so the value columns line up.
            .opacity(field.masked ? 1 : 0)
            .disabled(!field.masked)
            if field.kind == .password {
                Button { generatorOpen.toggle() } label: {
                    Image(systemName: "dice")
                }
                .buttonStyle(.borderless)
                .help(strings("create.generateSecret"))
                .accessibilityLabel(strings("create.generateSecret"))
                .popover(isPresented: $generatorOpen) {
                    GeneratorView(strings: strings) { value in
                        onGenerated(value)
                        generatorOpen = false
                    }
                }
            }
            if label == nil {
                Picker(strings("create.fieldType"), selection: $kind) {
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
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        #endif
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
                        .strokeBorder(Color.zannSeparator)
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
