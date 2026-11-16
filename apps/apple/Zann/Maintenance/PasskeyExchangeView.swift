import SwiftUI
import UniformTypeIdentifiers
import ZannCoreKit

struct PasskeyExchangeView: View {
    @ObservedObject var model: PasskeyExchangeModel
    let core: CoreFacade
    let strings: Strings
    @State private var targetID: String?
    @State private var format: PasskeyExchangeFormatFfi = .cxf
    @State private var choosing = false
    @State private var confirmExport = false
    @State private var pickerFailure: Error?
    private var target: PasskeyTargetFfi? { model.targets.first { $0.target.vaultId == targetID }?.target }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(strings("passkeyExchange.title")).font(.headline)
            Text(strings("passkeyExchange.help"))
            Picker(strings("passkeyExchange.target"), selection: $targetID) {
                Text(strings("passkeyExchange.selectTarget")).tag(String?.none)
                ForEach(model.targets, id: \.target.vaultId) { row in Text(row.name).tag(Optional(row.target.vaultId)) }
            }
            Picker(strings("passkeyExchange.format"), selection: $format) {
                Text("FIDO CXF").tag(PasskeyExchangeFormatFfi.cxf)
                Text("Bitwarden JSON").tag(PasskeyExchangeFormatFfi.bitwarden)
                Text("KeePassXC .passkey").tag(PasskeyExchangeFormatFfi.keepassXcPasskey)
                Text("KeePass XML").tag(PasskeyExchangeFormatFfi.keepassXml)
            }.disabled(model.preview != nil || model.busy)
            Button(strings("passkeyExchange.choose")) { choosing = true }.disabled(model.busy)
            if let preview = model.preview {
                Text(strings("passkeyExchange.preview", ["count": String(preview.credentials), "ignored": String(preview.ignoredRecords)]))
                Button(strings("passkeyExchange.import")) { if let target { Task { await model.restore(target: target) } } }.disabled(target == nil || model.busy)
            }
            Button(strings("passkeyExchange.export")) { confirmExport = true }.disabled(target == nil || model.busy)
            if let report = model.report { Text(strings("passkeyExchange.result", ["count": String(report.imported), "skipped": String(report.skippedExisting)])) }
            if model.busy { ProgressView() }
            if let error = model.failure ?? pickerFailure { Text(strings.message(for: error)).foregroundStyle(.red) }
        }
        .padding().frame(minWidth: 320)
        .task { await model.load() }
        .fileImporter(isPresented: $choosing, allowedContentTypes: [.data]) { result in
            switch result { case .success(let url): let selected = format; Task { await model.choose(url, format: selected) }; case .failure(let error): pickerFailure = error }
        }
        .sheet(isPresented: $confirmExport) {
            if let file = model.artifact {
                BackupExportPicker(file: file.file) { error in model.finishExport(error); confirmExport = false }
            } else if let target {
                ExportConfirmation(core: core, strings: strings, policyChange: false) { authorization, operation, _ in
                    await model.export(target: target, authorization: authorization, operation: operation)
                }
            }
        }
        .onChange(of: confirmExport) { visible in if !visible { model.finishExport(nil) } }
        .onDisappear { model.cancel() }
    }
}
