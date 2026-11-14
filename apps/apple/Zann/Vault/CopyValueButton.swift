import SwiftUI

/// One copy target for the value and its icon. Feedback keeps the same slot,
/// so copying never changes the row's geometry.
struct CopyValueButton: View {
    let value: String
    let fieldLabel: String
    let font: Font
    let singleLine: Bool
    let copied: Bool
    let strings: Strings
    let copyFeedback: String
    let onCopy: () -> Void

    var body: some View {
        Button(action: onCopy) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(value)
                    .font(font)
                    .lineLimit(singleLine ? 1 : nil)
                    .multilineTextAlignment(.leading)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    .frame(width: 16)
                    .foregroundStyle(copied ? Color.accentColor : Color.secondary)
                    .accessibilityHidden(true)
            }
        }
        .buttonStyle(CopySurfaceStyle(copied: copied))
        .help(copied ? copyFeedback : copyLabel)
        .accessibilityLabel(copyLabel)
        .accessibilityValue(copied ? copyFeedback : value)
    }

    private var copyLabel: String {
        strings("items.copyField", ["field": fieldLabel])
    }
}

private struct CopySurfaceStyle: ButtonStyle {
    let copied: Bool
    @State private var hovered = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, 6)
            .padding(.vertical, 4)
            .contentShape(Rectangle())
            .background(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(fill(pressed: configuration.isPressed))
            )
            .onHover { hovered = $0 }
    }

    private func fill(pressed: Bool) -> Color {
        if copied { return Color.accentColor.opacity(0.18) }
        if pressed { return Color.accentColor.opacity(0.15) }
        return hovered ? Color.accentColor.opacity(0.08) : .clear
    }
}
