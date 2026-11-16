import SwiftUI
import ZannCoreKit

/// A fresh native challenge. Rust owns factor verification and the single-use permit.
struct ExportConfirmation: View {
    let core: CoreFacade
    let strings: Strings
    let policyChange: Bool
    let confirm: @MainActor (ExportAuthorizationFfi, SessionOperationFfi, ExportPolicyFfi?) async -> Error?
    @Environment(\.dismiss) private var dismiss
    @State private var security: ExportSecurityFfi?
    @State private var factor: ExportFactorFfi = .devicePassword
    @State private var password = ""
    @State private var pin = ""
    @State private var operation: SessionOperationFfi?
    @State private var generation = 0
    @State private var failure: Error?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(strings("export.confirmTitle")).font(.headline)
            Text(strings(policyChange ? "export.policyHelp" : "settings.backups.plainWarningDesc"))
            if let security {
                Text(strings(security.policy == .anyConfiguredFactor ? "export.anyFactor" : "export.strictPolicy"))
                if policyChange {
                    Text(strings(security.policy == .anyConfiguredFactor ? "export.enableStrict" : "export.disableStrict"))
                }
                Picker(strings("export.factor"), selection: $factor) {
                    Text(strings("export.password")).tag(ExportFactorFfi.devicePassword)
                    if security.hardwareAvailable { Text(strings("export.hardware")).tag(ExportFactorFfi.hardwareKey) }
                    if security.biometricAvailable { Text(strings("export.biometric")).tag(ExportFactorFfi.biometric) }
                }
                SecureField(strings("unlock.devicePassword"), text: $password)
                    .accessibilityIdentifier("export.password")
                if factor == .hardwareKey {
                    SecureField(strings("export.pin"), text: $pin).accessibilityIdentifier("export.pin")
                }
                Button(strings("export.confirm")) { Task { await submit(security) } }
                    .accessibilityIdentifier("export.confirm")
                    .disabled(operation != nil)
            } else { ProgressView() }
            if operation != nil { ProgressView() }
            if let failure { Text(strings.message(for: failure)).foregroundStyle(.red) }
            Button(strings("common.cancel"), role: .cancel) { cancel(); dismiss() }
        }
        .padding().frame(minWidth: 280, idealWidth: 440)
        .task {
            let epoch = generation
            let result = await BlockingCore.run { Result { try core.exportSecurity() } }
            guard epoch == generation else { return }
            switch result {
            case .success(let value):
                security = value
                if value.policy == .passwordAndHardwareOrBiometric {
                    factor = value.hardwareAvailable ? .hardwareKey : .biometric
                }
            case .failure(let error): failure = error
            }
        }
        .onDisappear { cancel() }
    }

    @MainActor private func submit(_ security: ExportSecurityFfi) async {
        guard operation == nil else { return }
        failure = nil
        let result = Result { try SessionOperationFfi(timeoutMs: 120_000) }
        guard case .success(let pending) = result else {
            if case .failure(let error) = result { failure = error }; return
        }
        operation = pending
        let epoch = generation
        let proof = ExportStepUpFfi(password: password.isEmpty ? nil : password, factor: factor,
                                    pin: factor == .hardwareKey && !pin.isEmpty ? pin : nil)
        password = ""; pin = ""
        let authorization = await BlockingCore.run { Result { try core.authorizeExport(proof: proof, operation: pending) } }
        guard epoch == generation else { return }
        switch authorization {
        case .success(let permit):
            let policy: ExportPolicyFfi? = policyChange
                ? (security.policy == .anyConfiguredFactor ? .passwordAndHardwareOrBiometric : .anyConfiguredFactor) : nil
            let error = await confirm(permit, pending, policy)
            guard epoch == generation else { return }
            failure = error
            operation = nil
            if policyChange && error == nil { dismiss() }
        case .failure(let error): failure = error; operation = nil
        }
    }
    private func cancel() {
        generation += 1
        operation?.cancel()
        operation = nil
        password = ""; pin = ""
    }
}

struct ExportSecuritySection: View {
    let core: CoreFacade
    let unlocked: Bool
    let strings: Strings
    @State private var confirming = false
    var body: some View {
        Section(strings("export.securityTitle")) {
            Text(strings("export.policyHelp"))
            Button(strings("export.changePolicy")) { confirming = true }.disabled(!unlocked)
                .sheet(isPresented: $confirming) {
                    ExportConfirmation(core: core, strings: strings, policyChange: true) { authorization, _, policy in
                        guard let policy else { return CoreError.InvalidArgument("Missing export policy") }
                        let result = await BlockingCore.run { Result { try core.setExportPolicy(policy: policy, authorization: authorization) } }
                        if case .failure(let error) = result { return error }
                        return nil
                    }
                }
        }
    }
}
