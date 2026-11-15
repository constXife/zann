import SwiftUI
import ZannCoreKit

struct RecoveryView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var recovery: RecoveryModel
    @State private var discardUnsent = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(model.strings("recovery.title")).font(.title2.bold())
            Text(model.strings("recovery.help")).foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    ForEach(recovery.accounts, id: \.storageId) { account in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(account.name).font(.headline)
                            if let name = account.accountName { Text(name) }
                            Text(account.serverUrl).foregroundStyle(.secondary)
                            HStack {
                                Button(model.strings(account.enrolled ? "recovery.openAccount" : "recovery.enrollAccount")) {
                                    Task { await model.chooseSetupAccount(account) }
                                }
                                Button(model.strings("recovery.removeAccount"), role: .destructive) {
                                    Task { await recovery.prepare(account) }
                                }
                            }
                        }
                        Divider()
                    }
                }
            }
            Button(model.strings("wizard.connect")) { model.startConnecting(returnTo: .accounts) }
            Button(model.strings("recovery.resetDevice"), role: .destructive) { Task { await recovery.prepare(nil) } }
            if recovery.busy || model.busy { ProgressView().controlSize(.small) }
            if let error = recovery.error ?? model.error { Text(error).foregroundStyle(.red).textSelection(.enabled) }
            if let path = recovery.snapshotPath {
                Text(model.strings("recovery.snapshotSaved")).font(.caption)
                Text(path).font(.caption).textSelection(.enabled)
            }
        }
        .disabled(recovery.busy || model.busy)
        .padding(32).frame(maxWidth: 560)
        .task { await recovery.reload() }
        .sheet(isPresented: Binding(get: { recovery.preview != nil }, set: { value in if !value { Task { await recovery.cancel() } } })) {
            if let preview = recovery.preview { confirmation(preview) }
        }
    }
    private func confirmation(_ preview: RecoveryPreviewFfi) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(model.strings(recovery.selected == nil ? "recovery.resetDevice" : "recovery.removeAccount")).font(.title2.bold())
            if let account = recovery.selected {
                Text(account.serverUrl)
                if let name = account.accountName { Text(name) }
            }
            Text(model.strings(recovery.selected == nil ? "recovery.deviceWarning" : "recovery.accountWarning"))
            Text(model.strings("recovery.counts", ["accounts": String(preview.accounts), "items": String(preview.items), "pending": String(preview.pending), "dirty": String(preview.dirty), "history": String(preview.localHistory)]))
            if preview.hasUnsent {
                Toggle(model.strings("recovery.confirmUnsent"), isOn: $discardUnsent)
            }
            if let error = recovery.error { Text(error).foregroundStyle(.red).textSelection(.enabled) }
            HStack {
                Button(model.strings("common.cancel")) { Task { await recovery.cancel() } }
                Spacer()
                Button(model.strings("recovery.confirm"), role: .destructive) { Task { await recovery.confirm(discardUnsent: discardUnsent) } }
                    .disabled(preview.hasUnsent && !discardUnsent)
            }.disabled(recovery.busy)
        }
        .padding(24)
        #if os(iOS)
        .frame(maxWidth: 460)
        #else
        .frame(width: 460)
        #endif
        .onAppear { discardUnsent = false }
        .interactiveDismissDisabled(recovery.busy)
    }
}
