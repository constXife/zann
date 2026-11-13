import SwiftUI

/// Recovery stays with the server's status popover, never in the workspace.
struct SyncRecoveryActions: View {
    @ObservedObject var vault: VaultModel
    let strings: Strings
    @EnvironmentObject private var app: AppModel
    var body: some View {
        if let stale = vault.staleServer {
            ForgetServer(stale: stale, strings: strings)
        } else if vault.disconnected != nil, let error = app.error {
            Text(error).foregroundStyle(.red).textSelection(.enabled)
        }
    }
}

/// The way out of a server whose identity changed, behind a confirmation
/// that says what stays on this Mac.
private struct ForgetServer: View {
    let stale: VaultModel.StaleServer
    let strings: Strings
    @EnvironmentObject private var app: AppModel
    @State private var confirming = false

    var body: some View {
        Button(strings("settings.accounts.forgetServer")) { confirming = true }
            .disabled(app.busy)
            .alert(
                strings("settings.accounts.forgetServer"),
                isPresented: $confirming
            ) {
                Button(strings("settings.accounts.forgetServer"), role: .destructive) {
                    Task { await app.forgetStaleServer() }
                }
                Button(strings("common.cancel"), role: .cancel) {}
            } message: {
                Text(message)
            }
        // A failed forget keeps the vault open, so its error shows here.
        if let error = app.error {
            Text(error).foregroundStyle(.red).textSelection(.enabled)
        }
    }

    private var message: String {
        let confirm = strings("settings.accounts.forgetServerConfirm", ["server": stale.name])
        guard stale.pendingChanges > 0 else { return confirm }
        let pending = strings(
            "settings.accounts.forgetServerPending", ["count": String(stale.pendingChanges)]
        )
        return "\(confirm)\n\n\(pending)"
    }
}
