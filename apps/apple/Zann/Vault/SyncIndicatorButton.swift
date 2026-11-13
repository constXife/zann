import SwiftUI
import ZannCoreKit

/// A compact indicator beside the server/account selector. Details and the shared
/// state's available action live in a popover.
struct SyncIndicatorButton<Recovery: View>: View {
    let indicator: SyncIndicatorFfi
    let syncState: StorageSyncStateFfi?
    let error: String?
    let busy: Bool
    let strings: Strings
    let syncing: Bool
    let recovery: Recovery
    let onRefresh: () async -> Void
    let onSync: () async -> Void
    let onReconnect: () async -> Void

    @State private var showingDetails = false

    var body: some View {
        Button { showingDetails.toggle() } label: {
            Group {
                if syncing {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: Symbols.sync(indicator.state))
                        .foregroundStyle((indicator.needsAttention || error != nil) ? Color.red : Color.secondary)
                }
            }
            .frame(width: 18, height: 18)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityAddTraits(.isButton)
        .help(strings("sync.details"))
        .accessibilityLabel(strings("sync.details"))
        .accessibilityValue(statusLabel)
        .popover(isPresented: $showingDetails, arrowEdge: .bottom) {
            details
                .buttonStyle(.bordered)
                .task { await onRefresh() }
        }
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(statusLabel, systemImage: Symbols.sync(indicator.state))
                .font(.headline)
                .foregroundStyle((indicator.needsAttention || error != nil) ? Color.red : Color.primary)
            if let server = syncState?.serverUrl {
                Text(server)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            Text(lastSynced)
                .font(.callout)
                .foregroundStyle(.secondary)
            if let error {
                Text(error).foregroundStyle(.red).textSelection(.enabled)
            }
            if indicator.action != .noAction {
                Divider()
                action
            }
            recovery
        }
        .padding(16)
        .frame(width: 300, alignment: .leading)
    }

    @ViewBuilder private var action: some View {
        switch indicator.action {
        case .syncNow:
            HStack {
                Button(strings("settings.accounts.syncNow")) { Task { await onSync() } }
                    .disabled(busy)
                Spacer()
                Text("⌘R").foregroundStyle(.secondary).accessibilityHidden(true)
            }
        case .reconnect:
            Button(strings("settings.accounts.reconnect")) {
                showingDetails = false
                Task { await onReconnect() }
            }
            .disabled(busy)
        case .noAction:
            EmptyView()
        }
    }

    private var statusLabel: String {
        strings(indicator.labelKey, indicator.labelArgs)
    }

    private var lastSynced: String {
        guard let value = syncState?.lastSyncedAt,
              let date = ISO8601DateFormatter().date(from: value) else {
            return strings("sync.neverSynced")
        }
        let time = Calendar.current.isDateInToday(date)
            ? date.formatted(date: .omitted, time: .shortened)
            : date.formatted(date: .abbreviated, time: .shortened)
        return strings("sync.lastSynced", ["time": time])
    }
}
