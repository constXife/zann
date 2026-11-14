import SwiftUI
import ZannCoreKit

/// Creates the master password or unlocks with it. Strength and KDF rules
/// live in the core; this form only checks that both entries match.
struct MasterPasswordView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase
    let mode: AppModel.MasterMode

    @State private var password = ""
    @State private var confirmation = ""
    @FocusState private var focused: Bool

    private var phase: UnlockPhaseViewFfi { unlockPhaseView(phase: mode) }
    private var creating: Bool { phase.creating }
    private var feedback: PasswordFeedbackFfi { passwordCreationFeedback(password: password) }
    private var canSubmit: Bool {
        guard !password.isEmpty, !model.busy else { return false }
        return !creating || (password == confirmation && feedback.validationKey == nil)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(model.strings(phase.titleKey))
                .font(.title2.bold())
            Text(model.strings(phase.helpKey)).foregroundStyle(.secondary)
            if phase.account, let account = model.enrollmentAccount {
                Text(account.serverUrl).font(.caption)
                if let name = account.accountName { Text(name).font(.caption) }
            }
            if model.syncAfterUnlock {
                if mode == .unlock {
                    Text(model.strings("wizard.unlockSubtitle")).foregroundStyle(.secondary)
                }
                Text(model.strings("wizard.syncAfterUnlock")).foregroundStyle(.secondary)
            }
            SecureField(model.strings(phase.placeholderKey), text: $password)
                .focused($focused)
                .onSubmit(submit)
            if creating {
                if let key = feedback.strengthKey { Text(model.strings(key)).font(.caption).foregroundStyle(.secondary) }
                if let key = feedback.validationKey { Text(model.strings(key)).font(.caption).foregroundStyle(.red) }
                SecureField(model.strings(phase.confirmationKey), text: $confirmation)
                    .onSubmit(submit)
                if !confirmation.isEmpty && confirmation != password {
                    Text(model.strings("unlock.passwordMismatch")).foregroundStyle(.red)
                }
            }
            if let error = model.error {
                Text(error).foregroundStyle(.red).textSelection(.enabled)
            }
            HStack {
                Button(model.strings("recovery.title")) { model.showAccountRecovery() }.disabled(model.busy)

                if mode == .unlock && model.touchIDArmed {
                    Button {
                        Task {
                            await model.unlockWithTouchID()
                            focused = true
                        }
                    } label: {
                        Label(model.strings("unlock.touchId"), systemImage: "touchid")
                    }
                    .disabled(model.busy)
                }
                Spacer()
                if model.busy {
                    ProgressView().controlSize(.small)
                }
                Button(model.strings(creating ? "wizard.create" : "common.unlock"), action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSubmit)
            }
        }
        .textFieldStyle(.roundedBorder)
        .padding(32)
        .frame(maxWidth: 420)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear { focused = true }
        .onDisappear { password = ""; confirmation = "" }
        .task(id: scenePhase) {
            guard mode == .unlock, scenePhase == .active else { return }
            await model.unlockWithTouchIDAtStartup()
            focused = true
        }
        .onChange(of: model.screen) { _ in
            password = ""
            confirmation = ""
        }
    }

    private func submit() {
        guard canSubmit else { return }
        let password = password
        Task { await model.submit(password: password, mode: mode) }
    }
}
