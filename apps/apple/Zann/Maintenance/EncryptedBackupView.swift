import SwiftUI
import UniformTypeIdentifiers
import ZannCoreKit

struct EncryptedBackupView: View {
    @ObservedObject var model: EncryptedBackupModel
    let restoring: Bool
    let strings: Strings
    @Environment(\.dismiss) private var dismiss
    @State private var choosing = false
    @State private var kind: BackupRecipientKindFfi = .passphrase
    @State private var passphrase = ""
    @State private var pin = ""
    @State private var builtInUV = false
    @State private var slot: UInt32?
    @State private var sourceStorage: String?
    @State private var targetStorage: String?
    @State private var choosingFailure: Error?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(strings(restoring ? "backup.restoreTitle" : "backup.encryptedTitle")).font(.headline)
            if let artifact = model.artifact {
                BackupExportPicker(file: artifact.file) { error in
                    model.finishExport(error)
                    if error == nil { dismiss() }
                }
            } else if let report = model.imported {
                Text(strings("backup.imported", ["count": String(report.importedItems)]))
            } else if let inspection = model.inspection {
                restoreForm(inspection)
            } else if restoring {
                Button(strings("backup.choose")) { choosing = true }.disabled(model.busy)
                if !model.recipients.isEmpty {
                    Picker(strings("backup.recipient"), selection: $slot) {
                        Text(strings("backup.selectRecipient")).tag(UInt32?.none)
                        ForEach(model.recipients, id: \.index) { row in
                            Text("\(label(row.kind)) \(row.index + 1)").tag(Optional(row.index))
                        }
                    }
                    if let selected = model.recipients.first(where: { $0.index == slot }) {
                        credentials(selected.kind)
                        Button(strings("backup.open")) {
                            let recipient = takeRecipient(selected.kind)
                            Task { await model.open(slot: selected.index, recipient: recipient) }
                        }.disabled(model.busy)
                    }
                }
            } else {
                Text(strings("backup.portableHelp")).font(.caption)
                if let caps = model.capabilities {
                    Picker(strings("backup.recipient"), selection: $kind) {
                        ForEach(caps.recipients, id: \.self) { choice in Text(label(choice)).tag(choice) }
                    }
                    credentials(kind)
                    Button(strings("backup.addRecipient")) {
                        let recipient = takeRecipient(kind)
                        Task { await model.add(recipient) }
                    }.disabled(model.busy || !model.canExport || model.recipients.count >= Int(caps.maxRecipients))
                    ForEach(model.recipients, id: \.index) { row in Text("\(row.index + 1). \(label(row.kind))") }
                    Button(strings("backup.save")) { Task { await model.export() } }
                        .disabled(model.busy || !model.canExport)
                }
            }
            if !restoring && !model.canExport && model.artifact == nil && !model.busy {
                Button(strings("backup.restart")) { Task { await model.begin() } }
            }
            if model.busy { ProgressView() }
            if let failure = model.failure ?? choosingFailure { Text(strings.message(for: failure)).foregroundStyle(.red) }
            Button(strings("common.cancel"), role: .cancel) { model.cancel(); dismiss() }
        }
        .padding().frame(minWidth: 280, idealWidth: 480)
        .task { if !restoring { await model.begin() } }
        .fileImporter(isPresented: $choosing, allowedContentTypes: [.data]) { result in
            switch result {
            case .success(let url): slot = nil; Task { await model.chooseSource(url) }
            case .failure(let error): choosingFailure = error
            }
        }
        .onDisappear { passphrase = ""; pin = ""; model.cancel() }
    }
    @ViewBuilder private func credentials(_ kind: BackupRecipientKindFfi) -> some View {
        switch kind {
        case .passphrase:
            SecureField(strings("backup.passphrase"), text: $passphrase).accessibilityIdentifier("backup.passphrase")
        case .hardware:
            Text(strings("backup.hardwareHelp")).font(.caption)
            SecureField(strings("export.pin"), text: $pin)
            Toggle(strings("backup.builtInUV"), isOn: $builtInUV)
        case .biometric:
            Text(strings("backup.biometricHelp")).font(.caption)
        }
    }
    private func restoreForm(_ inspection: BackupInspectionFfi) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(strings("backup.verified", ["count": String(inspection.itemsCount)]))
            Picker(strings("backup.source"), selection: $sourceStorage) {
                Text(strings("backup.selectStorage")).tag(String?.none)
                ForEach(inspection.storages, id: \.id) { storage in Text(storage.name).tag(Optional(storage.id)) }
            }
            Picker(strings("backup.target"), selection: $targetStorage) {
                Text(strings("backup.selectStorage")).tag(String?.none)
                ForEach(model.targets, id: \.id) { storage in Text(storage.displayName).tag(Optional(storage.id)) }
            }
            if let sourceStorage, let targetStorage {
                Button(strings("backup.restore")) { Task { await model.restore(sourceStorage: sourceStorage, targetStorage: targetStorage) } }.disabled(model.busy || !model.canRestore)
            }
            Button(strings("backup.choose")) { choosing = true }.disabled(model.busy)
        }
    }
    private func takeRecipient(_ selected: BackupRecipientKindFfi) -> BackupRecipientFfi {
        let value = BackupRecipientFfi(kind: selected, passphrase: selected == .passphrase ? passphrase : nil,
            pin: selected == .hardware && !pin.isEmpty && !builtInUV ? pin : nil, builtInUv: selected == .hardware && builtInUV)
        passphrase = ""; pin = ""
        return value
    }
    private func label(_ kind: BackupRecipientKindFfi) -> String {
        strings(kind == .passphrase ? "backup.passphrase" : (kind == .hardware ? "export.hardware" : "export.biometric"))
    }
}
