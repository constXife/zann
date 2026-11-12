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
                                label: strings.fieldLabel(field.key),
                                compact: compact,
                                revealed: revealed.contains(index) || revealAll,
                                copied: copied == index,
                                revealHelp: strings(revealed.contains(index) ? "common.hide" : "common.reveal"),
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

    private var subtitle: String {
        let type = strings.typeLabel(detail.typeID)
        return detail.path.isEmpty ? type : "\(detail.path) · \(type)"
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

    private var valueAndEye: some View {
        HStack(alignment: .center, spacing: 12) {
            if let totp = field.totp {
                TotpValue(params: totp, copied: copied, onCopy: onCopy)
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
            }
            // The eye keeps its slot on every row so values line up. A one-time
            // code is shown as a code, never as its secret, so it has no eye.
            Button(action: onToggleReveal) {
                Image(systemName: revealed ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            .help(revealHelp)
            .opacity(canReveal ? 1 : 0)
            .disabled(!canReveal)
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
    let onCopy: (String) -> Void

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            if let code = try? generateTotp(params: params) {
                Button { onCopy(code.code) } label: {
                    HStack {
                        Text(grouped(code.code)).font(.title3.monospaced())
                        Spacer()
                        Text("\(code.remainingSeconds)s")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                }
                .buttonStyle(CopySurfaceStyle(copied: copied))
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

/// The whole value surface is the copy target; pressing and a successful copy
/// tint that surface without changing its text or geometry.
private struct CopySurfaceStyle: ButtonStyle {
    let copied: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .contentShape(Rectangle())
            .background(
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(fill(pressed: configuration.isPressed))
            )
    }

    private func fill(pressed: Bool) -> Color {
        if copied { return Color.accentColor.opacity(0.18) }
        return pressed ? Color.primary.opacity(0.1) : Color.clear
    }
}
