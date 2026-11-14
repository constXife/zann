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
    @State private var showLoadingIndicator = false

    var body: some View {
        Group {
            if let detail = vault.detail {
                ItemDetailContent(
                    detail: detail, strings: strings, preferences: preferences,
                    revealAll: revealAll && detail.id == vault.selectedItemID,
                    selectionGeneration: vault.detailSelectionGeneration
                )
                // The previous card stays visually stable during replacement,
                // but none of its actions may target the newly selected row.
                .disabled(detail.id != vault.selectedItemID)
                .accessibilityHidden(detail.id != vault.selectedItemID)
            } else if let error = vault.error {
                placeholder(error)
            } else if vault.selectedItemID != nil {
                Group {
                    if showLoadingIndicator { ProgressView() }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if vault.awaitingFirstSync && vault.visibleItems.isEmpty {
                Color.clear
            } else {
                placeholder(strings("items.detailsHint"))
            }
        }
        .task(id: vault.selectedItemID) {
            showLoadingIndicator = false
            guard vault.detail == nil, vault.selectedItemID != nil else { return }
            try? await Task.sleep(nanoseconds: 150_000_000)
            guard !Task.isCancelled, vault.detail == nil else { return }
            showLoadingIndicator = true
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
    let selectionGeneration: Int

    @State private var stateGeneration: Int?
    @State private var revealTasks: [Int: Task<Void, Never>] = [:]
    @State private var revealed: Set<Int> = []
    @State private var copied: Int?
    @State private var copyFeedbackTask: Task<Void, Never>?
    /// Below this width a label beside its value leaves the value too little
    /// room, so every row puts its label above instead.
    @State private var compact = false
    private static let compactWidth: CGFloat = 420

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 14) {
                    ItemIcon(typeID: detail.typeId, size: 52)
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
                            ItemDetailFieldRow(
                                field: field,
                                label: strings.fieldLabel(field.labelKey),
                                compact: compact,
                                revealed: (stateGeneration == selectionGeneration && revealed.contains(index)) || revealAll,
                                copied: stateGeneration == selectionGeneration && copied == index,
                                strings: strings,
                                copyFeedback: copyFeedback,
                                revealHelp: strings(stateGeneration == selectionGeneration && revealed.contains(index) ? "common.hide" : "common.reveal"),
                                onCopy: { copy($0, index: index) },
                                onToggleReveal: { toggleReveal(index) }
                            )
                        }
                    }
                    .id(detail.id)
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
        .onChange(of: selectionGeneration) { _ in resetInteractions() }
        .onDisappear { resetInteractions() }
    }

    private func resetInteractions() {
        stateGeneration = selectionGeneration
        revealed.removeAll()
        copied = nil
        copyFeedbackTask?.cancel()
        for task in revealTasks.values { task.cancel() }
        revealTasks.removeAll()
    }

    private var copyFeedback: String {
        preferences.clipboardClearSeconds > 0
            ? strings("items.copiedClears", ["seconds": String(preferences.clipboardClearSeconds)])
            : strings("common.copied")
    }

    /// The type, after the folder the item lives in. `path` ends with the
    /// item's own name, which the title already shows.
    private var subtitle: String {
        let type = strings.typeLabel(detail.typeId)
        return folderOf(path: detail.path).map { "\($0) · \(type)" } ?? type
    }

    private func copy(_ value: String, index: Int) {
        if stateGeneration != selectionGeneration { resetInteractions() }
        Clipboard.copy(
            value,
            clearAfter: preferences.clipboardClearSeconds,
            onlyIfUnchanged: preferences.clipboardClearIfUnchanged
        )
        copied = index
        copyFeedbackTask?.cancel()
        copyFeedbackTask = Task {
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            guard !Task.isCancelled else { return }
            copied = nil
        }
    }

    /// The eye button holds for `auto_hide_reveal_seconds`, then masks again.
    private func toggleReveal(_ index: Int) {
        if stateGeneration != selectionGeneration { resetInteractions() }
        revealTasks[index]?.cancel()
        guard revealed.insert(index).inserted else {
            revealed.remove(index)
            return
        }
        let seconds = preferences.autoHideRevealSeconds
        guard seconds > 0 else { return }
        let generation = selectionGeneration
        let expectedGeneration = $stateGeneration
        let revealedFields = $revealed
        revealTasks[index] = Task {
            try? await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000)
            guard !Task.isCancelled, expectedGeneration.wrappedValue == generation else { return }
            revealedFields.wrappedValue.remove(index)
        }
    }
}
