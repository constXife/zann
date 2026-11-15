import SwiftUI

struct MaintenanceSections: View {
    @ObservedObject var maintenance: MaintenanceModel
    let unlocked: Bool
    let strings: Strings
    @State private var confirmExport = false

    var body: some View {
        Section(strings("settings.tabs.backups")) {
            Text(strings("settings.backups.exportDesc"))
            exportAction
            Button(strings("maintenance.snapshotCreate")) { Task { await maintenance.createSnapshot() } }
                .accessibilityIdentifier("maintenance.snapshot")
                .disabled(maintenance.busy)
            Text(strings("maintenance.snapshotHelp"))
                .font(.caption).foregroundStyle(.secondary)
            ForEach(maintenance.snapshots, id: \.path) { row in
                Text(row.createdAt).font(.caption).textSelection(.enabled)
                    .accessibilityIdentifier("maintenance.snapshotResult")
            }
        }
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
                        .font(.caption).textSelection(.enabled)
                }
            }
        }
        if maintenance.busy { ProgressView().accessibilityIdentifier("maintenance.busy") }
        if let failure = maintenance.failure { Text(strings.message(for: failure)).foregroundStyle(.red).textSelection(.enabled) }
    }

    private var exportAction: some View {
        Button(strings("settings.backups.exportAction")) { confirmExport = true }
        .accessibilityIdentifier("maintenance.export")
        .disabled(!unlocked || maintenance.busy)
        // Presentation needs a concrete row in the Form's view hierarchy.
        .alert(strings("settings.backups.plainWarningTitle"), isPresented: $confirmExport) {
            Button(strings("settings.backups.exportAction")) { Task { await maintenance.prepareExport() } }
            Button(strings("common.cancel"), role: .cancel) {}
        } message: { Text(strings("settings.backups.plainWarningDesc")) }
        .sheet(item: .constant(maintenance.export)) { artifact in
            BackupExportPicker(file: artifact.file, finished: { failure in
                maintenance.finishExport(id: artifact.id, failure: failure)
            })
            .onDisappear { maintenance.finishExport(id: artifact.id) }
        }
    }
}
