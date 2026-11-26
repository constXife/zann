import SwiftUI
import ZannCoreKit

struct ItemHistoryView: View {
    @ObservedObject var history: ItemHistoryModel
    let strings: Strings
    let preferences: DevicePreferencesFfi
    let revealAll: Bool
    let close: () -> Void
    let restore: (ItemHistorySummaryFfi) async -> Void
    @State private var confirmation: ItemHistorySummaryFfi?
    @State private var askingToRestore = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(strings("items.historyOpen")).font(.headline)
                    Text(history.title).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                Button(strings("common.close"), action: close)
                    .keyboardShortcut(.cancelAction)
                    .disabled(history.restoring)
            }.padding()
            Divider()
            if let failure = history.failure {
                HStack {
                    Text(strings.message(for: failure)).foregroundStyle(.red)
                    Spacer()
                    Button(strings("common.retry")) { Task { await history.refresh() } }
                }.padding().disabled(history.restoring)
            }
            if history.loadingList {
                ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if history.entries.isEmpty {
                if history.failure == nil {
                    Text(strings("items.historyEmpty"))
                        .foregroundStyle(.secondary).frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            } else {
                GeometryReader { proxy in
                    if proxy.size.width >= 620 {
                        HStack(spacing: 0) {
                            versions.frame(width: 210)
                            Divider()
                            preview
                        }
                    } else {
                        VStack(spacing: 0) {
                            versions.frame(height: min(180, proxy.size.height / 3))
                            Divider()
                            preview
                        }
                    }
                }
            }
        }
        .task { await history.refresh() }
        .alert(strings("items.restorePreviousTitle"), isPresented: $askingToRestore,
               presenting: confirmation) { entry in
            Button(strings("common.cancel"), role: .cancel) {}
            Button(strings("items.restorePreviousConfirm"), role: .destructive) {
                Task { await restore(entry) }
            }
        } message: { entry in
            Text("v\(entry.version) · \(strings("items.restorePreviousMessage"))")
        }
    }

    private var versions: some View {
        List(history.entries, id: \.id, selection: Binding(
            get: { history.selected?.id },
            set: { id in
                guard let entry = history.entries.first(where: { $0.id == id }),
                      entry.id != history.selected?.id else { return }
                Task { await history.select(entry) }
            }
        )) { entry in
            VStack(alignment: .leading, spacing: 3) {
                Text("v\(entry.version) · \(strings(entry.changeLabelKey))").font(.headline)
                Text(RegionalDates().timestamp(entry.createdAt) ?? strings("common.dateUnavailable"))
                if !entry.author.isEmpty { Text(entry.author).lineLimit(1) }
                if entry.pending { Text(strings("items.historyLocalVersion")).foregroundStyle(.secondary) }
            }
            .font(.caption)
            .padding(.vertical, 3)
            .tag(entry.id)
        }.disabled(history.restoring)
    }

    @ViewBuilder private var preview: some View {
        if let detail = history.preview, let selected = history.selected {
            VStack(spacing: 0) {
                ItemDetailContent(detail: detail, faviconRgba: nil, strings: strings, preferences: preferences,
                                  revealAll: revealAll, selectionGeneration: history.previewGeneration)
                    .id(history.previewGeneration)
                Divider()
                HStack {
                    Text("v\(selected.version)").foregroundStyle(.secondary)
                    Spacer()
                    Button(strings("items.historyRestore")) {
                        confirmation = selected
                        askingToRestore = true
                    }
                }.padding()
            }.disabled(history.restoring)
        } else if history.loadingVersion {
            ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            Text(strings("items.historyVersionMissing")).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}
