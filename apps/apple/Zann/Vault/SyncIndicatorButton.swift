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
            .appleTouchTarget()
        }
        .accessibilityElement(children: .ignore)
        .accessibilityAddTraits(.isButton)
        .help(strings("sync.details"))
        .accessibilityLabel(strings("sync.details"))
        .accessibilityValue(statusLabel)
        .accessibilityIdentifier("workspace.sync")
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
                .accessibilityIdentifier("sync.status.\(indicator.labelKey)")
            if let server = syncState?.serverUrl {
                Text(server)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            Text(lastSynced)
                .font(.callout)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier(lastSyncedIdentifier)
            if let error {
                Text(error).foregroundStyle(.red).textSelection(.enabled)
                    .accessibilityIdentifier("sync.error")
            }
            if indicator.action != .noAction {
                Divider()
                action
            }
            recovery
            #if os(iOS)
            Button { showingDetails = false } label: { Text(strings("common.close")).appleTouchTarget() }
            #endif
        }
        .padding(16)
        #if os(macOS)
        .frame(width: 300, alignment: .leading)
        #else
        .frame(maxWidth: 360, alignment: .leading)
        #endif
    }

    @ViewBuilder private var action: some View {
        switch indicator.action {
        case .syncNow:
            HStack {
                Button(strings("settings.accounts.syncNow")) { Task { await onSync() } }
                    .disabled(busy)
                    .accessibilityIdentifier("sync.run")
                Spacer()
                #if os(macOS)
                Text("⌘R").foregroundStyle(.secondary).accessibilityHidden(true)
                #endif
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

    private var lastSyncedIdentifier: String {
        if let timestamp = syncState?.lastSyncedAt { return "sync.lastSynced.\(timestamp)" }
        return "sync.neverSynced"
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
