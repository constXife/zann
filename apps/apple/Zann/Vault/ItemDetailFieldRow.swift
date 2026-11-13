import SwiftUI
import ZannCoreKit

struct ItemDetailFieldRow: View {
    let field: ItemDetailFieldFfi
    let label: String
    let compact: Bool
    let revealed: Bool
    let copied: Bool
    let strings: Strings
    let copyFeedback: String
    let revealHelp: String
    let onCopy: (String) -> Void
    let onToggleReveal: () -> Void

    @Environment(\.openURL) private var openURL
    @State private var openFailed = false
    private static let mask = maskedValue()
    private static let accessoryWidth: CGFloat = 22

    var body: some View {
        Group {
            if compact {
                VStack(alignment: .leading, spacing: 2) {
                    labelText.padding(.horizontal, 6)
                    valueAndActions
                }
            } else {
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    labelText.lineLimit(2).frame(width: 120, alignment: .leading)
                    valueAndActions
                }
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .alert(strings("items.websiteOpenFailed"), isPresented: $openFailed) {
            Button(strings("common.close"), role: .cancel) {}
        }
    }

    private var labelText: some View {
        Text(label).foregroundStyle(.secondary)
    }

    private var valueAndActions: some View {
        HStack(spacing: 8) {
            if let totp = field.totp {
                TotpValue(
                    params: totp, label: label, copied: copied,
                    strings: strings, copyFeedback: copyFeedback,
                    accessoryWidth: Self.accessoryWidth, onCopy: onCopy
                )
            } else {
                CopyValueButton(
                    value: shown, fieldLabel: label,
                    font: field.masked ? .body.monospaced() : .body,
                    singleLine: field.masked, copied: copied,
                    strings: strings, copyFeedback: copyFeedback,
                    onCopy: { onCopy(field.value) }
                )
                if field.masked {
                    Button(action: onToggleReveal) {
                        Image(systemName: revealed ? "eye.slash" : "eye")
                    }
                    .buttonStyle(.borderless)
                    .help(revealHelp)
                    .accessibilityLabel(revealHelp)
                    .frame(width: Self.accessoryWidth)
                }
            }
            if let websiteURL {
                Button {
                    openURL(websiteURL) { accepted in openFailed = !accepted }
                } label: {
                    Image(systemName: "arrow.up.right.square")
                }
                .buttonStyle(.borderless)
                .help(strings("items.openWebsite"))
                .accessibilityLabel(strings("items.openWebsite"))
                .frame(width: Self.accessoryWidth)
            }
        }
    }

    private var websiteURL: URL? {
        field.websiteUrl.flatMap { URL(string: $0) }
    }

    private var shown: String {
        field.masked && !revealed ? Self.mask : field.value
    }
}
