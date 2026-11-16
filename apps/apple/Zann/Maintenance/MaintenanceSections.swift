import SwiftUI

struct MaintenanceSections: View {
    @EnvironmentObject private var app: AppModel
    @ObservedObject var maintenance: MaintenanceModel
    let unlocked: Bool
    let strings: Strings
    @State private var confirmExport = false
    @State private var encryptedExport = false
    @State private var encryptedRestore = false
    @State private var passkeys = false

    var body: some View {
        Section(strings("settings.tabs.backups")) {
            Text(strings("settings.backups.exportDesc"))
            exportAction
            Button(strings("passkeyExchange.title")) { passkeys = true }.disabled(!unlocked || maintenance.busy)
                .sheet(isPresented: $passkeys, onDismiss: { Task { await app.vault?.refreshLocalContents() } }) { PasskeyExchangeView(model: maintenance.passkeys, core: maintenance.core, strings: strings) }
            Button(strings("backup.encryptedTitle")) { encryptedExport = true }.disabled(!unlocked || maintenance.busy)
                .sheet(isPresented: $encryptedExport) { EncryptedBackupView(model: maintenance.encrypted, restoring: false, strings: strings) }
            Button(strings("backup.restoreTitle")) { encryptedRestore = true }.disabled(!unlocked || maintenance.busy)
                .sheet(isPresented: $encryptedRestore) { EncryptedBackupView(model: maintenance.encrypted, restoring: true, strings: strings) }
            Button(strings("maintenance.snapshotCreate")) { Task { await maintenance.createSnapshot() } }
                .accessibilityIdentifier("maintenance.snapshot")
                .disabled(maintenance.busy)
            Text(strings("maintenance.snapshotHelp"))
                .font(.caption).foregroundStyle(.secondary)
            // Read-only results remain labels, without native text-selection focus.
            ForEach(maintenance.snapshots, id: \.path) { row in
                Text(row.createdAt).font(.caption)
                    .accessibilityIdentifier("maintenance.snapshotResult")
            }
        }
        .onChange(of: unlocked) { value in if !value { encryptedExport = false; encryptedRestore = false; confirmExport = false; passkeys = false } }
        Section(strings("maintenance.verifyTitle")) {
            Button(strings("maintenance.verifyAction")) { Task { await maintenance.verify() } }
                .accessibilityIdentifier("maintenance.verify")
                .disabled(!unlocked || maintenance.busy)
            if let report = maintenance.verification {
                Text(strings(report.databaseOk && report.problems.isEmpty ? "maintenance.verifyOK" : "maintenance.verifyProblems"))
                    .accessibilityIdentifier("maintenance.verifyResult")
                Text(strings("maintenance.verifyCounts", ["items": String(report.itemsOk), "checked": String(report.itemsChecked),
                                                          "skipped": String(report.vaultsSkipped)]))
                ForEach(Array(report.problems.enumerated()), id: \.offset) { _, problem in
                    Text([problem.kind, problem.vaultName, problem.itemPath, problem.detail].compactMap { $0 }.joined(separator: " · "))
                        .font(.caption)
                }
            }
        }
        if maintenance.busy { ProgressView().accessibilityIdentifier("maintenance.busy") }
        if let failure = maintenance.failure { Text(strings.message(for: failure)).foregroundStyle(.red) }
    }

    private var exportAction: some View {
        Button(strings("settings.backups.exportAction")) { confirmExport = true }
        .accessibilityIdentifier("maintenance.export")
        .disabled(!unlocked || maintenance.busy)
        .sheet(isPresented: $confirmExport) {
            if let artifact = maintenance.export {
                BackupExportPicker(file: artifact.file, finished: { failure in
                    maintenance.finishExport(id: artifact.id, failure: failure)
                    confirmExport = false
                })
                .onDisappear { maintenance.finishExport(id: artifact.id) }
            } else {
                ExportConfirmation(core: maintenance.core, strings: strings, policyChange: false) { authorization, operation, _ in
                    await maintenance.prepareExport(authorization: authorization, operation: operation)
                    return maintenance.failure
                }
            }
        }
    }
}
