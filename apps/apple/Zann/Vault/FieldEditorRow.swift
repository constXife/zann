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

    var body: some View {
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
