import SwiftUI

/// Creates the master password or unlocks with it. Strength and KDF rules
/// live in the core; this form only checks that both entries match.
struct MasterPasswordView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase
    let mode: AppModel.MasterMode

    @State private var password = ""
    @State private var confirmation = ""
    @FocusState private var focused: Bool

    private var creating: Bool { mode == .create || mode == .accountCreate }
    private var account: Bool { mode == .accountCreate || mode == .accountUnlock }
    private var title: String {
        model.strings(account ? (creating ? "unlock.accountCreateTitle" : "unlock.accountTitle") : (creating ? "unlock.createTitle" : "unlock.title"))
    }
    private var canSubmit: Bool {
        guard !password.isEmpty, !model.busy else { return false }
        return !creating || password == confirmation
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.title2.bold())
            if creating {
                Text(model.strings(account ? "unlock.accountHelp" : "unlock.deviceHelp"))
                    .foregroundStyle(.secondary)
            }
            if model.syncAfterUnlock {
                if mode == .unlock {
                    Text(model.strings("wizard.unlockSubtitle")).foregroundStyle(.secondary)
                }
                Text(model.strings("wizard.syncAfterUnlock")).foregroundStyle(.secondary)
            }
            SecureField(model.strings(account ? "unlock.accountPlaceholder" : "unlock.passwordPlaceholder"), text: $password)
                .focused($focused)
                .onSubmit(submit)
            if creating {
                SecureField(model.strings("unlock.confirmPassword"), text: $confirmation)
                    .onSubmit(submit)
                if !confirmation.isEmpty && confirmation != password {
                    Text(model.strings("unlock.passwordMismatch")).foregroundStyle(.red)
                }
            }
            if let error = model.error {
                Text(error).foregroundStyle(.red).textSelection(.enabled)
            }
            HStack {
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
