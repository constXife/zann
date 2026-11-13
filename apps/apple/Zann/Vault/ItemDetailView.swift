import SwiftUI
import ZannCoreKit

/// The detail workspace: header, then the projected fields in one grouped box,
/// Passwords-style. Reveal, copy and TOTP live here only.
struct ItemDetailView: View {
    @ObservedObject var vault: VaultModel
    let strings: Strings
    let preferences: DevicePreferencesFfi
    /// Held reveal modifier; never mutates the per-field reveal state.
    let revealAll: Bool

    var body: some View {
        if let detail = vault.detail {
            ItemDetailContent(
                detail: detail, strings: strings, preferences: preferences, revealAll: revealAll
            )
            // Fresh reveal and copy state for every item.
            .id(detail.id)
        } else if let error = vault.error {
            placeholder(error)
        } else if vault.selectedItemID != nil {
            ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            placeholder(strings("items.detailsHint"))
        }
    }

    private func placeholder(_ text: String) -> some View {
        Text(text)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .padding(32)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct ItemDetailContent: View {
    let detail: VaultModel.Detail
    let strings: Strings
    let preferences: DevicePreferencesFfi
    let revealAll: Bool

    @State private var revealed: Set<Int> = []
    @State private var copied: Int?
    /// Below this width a label beside its value leaves the value too little
    /// room, so every row puts its label above instead.
    @State private var compact = false
    private static let compactWidth: CGFloat = 420

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 14) {
                    ItemIcon(typeID: detail.typeID, size: 52)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(detail.title).font(.title2.bold()).textSelection(.enabled)
                        Text(subtitle).foregroundStyle(.secondary)
                    }
                }
                if detail.fields.isEmpty {
                    Text(strings("items.noFields")).foregroundStyle(.secondary)
                } else {
                    VStack(spacing: 0) {
                        ForEach(Array(detail.fields.enumerated()), id: \.offset) { index, field in
                            if index > 0 {
                                Divider().padding(.leading, 12)
                            }
                            FieldRow(
                                field: field,
                                label: strings.fieldLabel(field.labelKey),
                                compact: compact,
                                revealed: revealed.contains(index) || revealAll,
                                copied: copied == index,
                                revealHelp: strings(revealed.contains(index) ? "common.hide" : "common.reveal"),
                                copyHelp: strings(copied == index ? "common.copied" : "common.copy"),
                                onCopy: { copy($0, index: index) },
                                onToggleReveal: { toggleReveal(index) }
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
                    .onGeometryChange(for: Bool.self) { proxy in
                        proxy.size.width < Self.compactWidth
                    } action: { compact = $0 }
                }
            }
            .padding(24)
            .frame(maxWidth: 680, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    /// The type, after the folder the item lives in. `path` ends with the
    /// item's own name, which the title already shows.
    private var subtitle: String {
        let type = strings.typeLabel(detail.typeID)
        return folderOf(path: detail.path).map { "\($0) · \(type)" } ?? type
    }

    private func copy(_ value: String, index: Int) {
        Clipboard.copy(
            value,
            clearAfter: preferences.clipboardClearSeconds,
            onlyIfUnchanged: preferences.clipboardClearIfUnchanged
        )
        copied = index
        Task {
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            if copied == index { copied = nil }
        }
    }

    /// The eye button holds for `auto_hide_reveal_seconds`, then masks again.
    private func toggleReveal(_ index: Int) {
        guard revealed.insert(index).inserted else {
            revealed.remove(index)
            return
        }
        let seconds = preferences.autoHideRevealSeconds
        guard seconds > 0 else { return }
        Task {
            try? await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000)
            revealed.remove(index)
        }
    }
}

private struct FieldRow: View {
    let field: ItemDetailFieldFfi
    let label: String
    /// The label sits above the value instead of beside it.
    let compact: Bool
    let revealed: Bool
    let copied: Bool
    let revealHelp: String
    let copyHelp: String
    let onCopy: (String) -> Void
    let onToggleReveal: () -> Void

    /// zann-ui-core's fixed-width mask, the same one COSMIC shows.
    private static let mask = maskedValue()

    var body: some View {
        Group {
            if compact {
                VStack(alignment: .leading, spacing: 2) {
                    labelText.padding(.horizontal, 8)
                    valueAndEye
                }
            } else {
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    labelText
                        .lineLimit(2)
                        .frame(width: 140, alignment: .leading)
                    valueAndEye
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private var labelText: some View {
        Text(label).foregroundStyle(.secondary)
    }

    /// Width of the trailing slot every row keeps, so values line up: the
    /// eye of a masked value, or the countdown of a one-time code.
    static let accessoryWidth: CGFloat = 22

    private var valueAndEye: some View {
        HStack(alignment: .center, spacing: 12) {
            if let totp = field.totp {
                // A one-time code shows as a code, never as its secret, so its
                // slot holds the countdown instead of an eye.
                TotpValue(params: totp, copied: copied, copyHelp: copyHelp, onCopy: onCopy)
            } else {
                Button { onCopy(field.value) } label: {
                    Text(shown)
                        // Only secrets are set in a fixed-width face; plain
                        // values read as ordinary text and wrap. A secret
                        // keeps one line, so revealing it never resizes the row.
                        .font(field.masked ? .body.monospaced() : .body)
                        .lineLimit(field.masked ? 1 : nil)
                        .multilineTextAlignment(.leading)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .buttonStyle(CopySurfaceStyle(copied: copied))
                .help(copyHelp)
                Button(action: onToggleReveal) {
                    Image(systemName: revealed ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .help(revealHelp)
                .frame(width: Self.accessoryWidth)
                .opacity(canReveal ? 1 : 0)
                .disabled(!canReveal)
            }
        }
    }

    private var canReveal: Bool {
        field.masked && field.totp == nil
    }

    private var shown: String {
        field.masked && !revealed ? Self.mask : field.value
    }
}

private struct TotpValue: View {
    let params: TotpParamsFfi
    let copied: Bool
    let copyHelp: String
    let onCopy: (String) -> Void

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            if let code = try? generateTotp(params: params) {
                HStack(alignment: .center, spacing: 12) {
                    Button { onCopy(code.code) } label: {
                        Text(grouped(code.code))
                            .font(.title3.monospaced())
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .buttonStyle(CopySurfaceStyle(copied: copied))
                    .help(copyHelp)
                    TotpCountdown(remaining: code.remainingSeconds, period: code.period)
                        .frame(width: FieldRow.accessoryWidth)
                }
            } else {
                Text("invalid one-time code")
                    .foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private func grouped(_ code: String) -> String {
        let split = code.index(code.startIndex, offsetBy: code.count / 2)
        return "\(code[..<split]) \(code[split...])"
    }
}

/// How long the code shown stays valid: a ring that empties over the period,
/// with the seconds left in its help. It turns orange in the last five
/// seconds, when copying the next code is the safer bet.
private struct TotpCountdown: View {
    let remaining: UInt32
    let period: UInt32

    var body: some View {
        let fraction = period > 0 ? Double(remaining) / Double(period) : 0
        let ending = remaining <= 5
        ZStack {
            Circle().stroke(Color.secondary.opacity(0.25), lineWidth: 2)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(ending ? Color.orange : Color.secondary, style: StrokeStyle(lineWidth: 2, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: remaining)
        }
        .frame(width: 14, height: 14)
        .help("\(remaining)s")
        .accessibilityLabel("\(remaining)s")
    }
}

/// The whole value surface is the copy target. Hovering it tints it and shows
/// a copy glyph at its trailing edge, so clicking to copy is discoverable; a
/// successful copy keeps the tint and shows a checkmark. The text and the
/// geometry never change, so neither shifts the row.
private struct CopySurfaceStyle: ButtonStyle {
    let copied: Bool

    func makeBody(configuration: Configuration) -> some View {
        CopySurface(configuration: configuration, copied: copied)
    }
}

private struct CopySurface: View {
    let configuration: ButtonStyleConfiguration
    let copied: Bool
    @State private var hovering = false

    /// Room kept at the trailing edge for the glyph, so it never covers text.
    private static let glyphWidth: CGFloat = 16

    var body: some View {
        configuration.label
            .padding(.trailing, Self.glyphWidth + 4)
            .overlay(alignment: .trailing) {
                Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    .font(.caption)
                    .foregroundStyle(copied ? Color.accentColor : Color.secondary)
                    .frame(width: Self.glyphWidth)
                    .opacity(copied || hovering ? 1 : 0)
                    .accessibilityHidden(true)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .contentShape(Rectangle())
            .background(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(fill)
            )
            .onHover { hovering = $0 }
    }

    private var fill: Color {
        if copied { return Color.accentColor.opacity(0.18) }
        if configuration.isPressed { return Color.primary.opacity(0.1) }
        return hovering ? Color.primary.opacity(0.05) : Color.clear
    }
}
