import SwiftUI
import ZannCoreKit

/// Creates the master password or unlocks with it. Strength and KDF rules
/// live in the core; this form only checks that both entries match.
struct MasterPasswordView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.dynamicTypeSize) private var textSize
    let mode: AppModel.MasterMode

    @State private var password = ""
    @State private var confirmation = ""
    #if os(macOS)
    @StateObject private var keyboard = KeyboardInputSource()
    #endif
    private enum Field: Hashable { case password, confirmation }
    @FocusState private var focused: Field?

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
            passwordInput(model.strings(phase.placeholderKey), text: $password, field: .password)
            if creating {
                if let key = feedback.strengthKey { Text(model.strings(key)).font(.caption).foregroundStyle(.secondary) }
                if let key = feedback.validationKey { Text(model.strings(key)).font(.caption).foregroundStyle(.red) }
                passwordInput(model.strings(phase.confirmationKey), text: $confirmation, field: .confirmation)
                if !confirmation.isEmpty && confirmation != password {
                    Text(model.strings("unlock.passwordMismatch")).foregroundStyle(.red)
                }
            }
            if let error = model.error {
                Text(error).foregroundStyle(.red).textSelection(.enabled)
            }
            actionsLayout {
                Button(model.strings("recovery.title")) { model.showAccountRecovery() }.disabled(model.busy)

                if mode == .unlock && model.touchIDArmed {
                    Button {
                        Task {
                            await model.unlockWithTouchID()
                            focused = .password
                        }
                    } label: {
                        #if os(iOS)
                        Label(model.strings("unlock.biometrics"), systemImage: "lock.open").appleTouchTarget()
                        #else
                        Label(model.strings("unlock.touchId"), systemImage: "touchid")
                        #endif
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
        #if os(iOS)
        .controlSize(.large)
        .padding(20)
        #else
        .padding(32)
        #endif
        .frame(maxWidth: 420)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear { focused = .password }
        #if os(macOS)
        .onChange(of: focused) { _ in keyboard.refresh() }
        #endif
        .onDisappear { password = ""; confirmation = "" }
        .onChange(of: scenePhase) { if $0 != .active { password = ""; confirmation = "" } }
        .task(id: scenePhase) {
            guard mode == .unlock, scenePhase == .active else { return }
            await model.unlockWithTouchIDAtStartup()
            focused = .password
        }
        .onChange(of: model.screen) { _ in
            password = ""
            confirmation = ""
        }
    }

    private var actionsLayout: AnyLayout {
        textSize.isAccessibilitySize ? AnyLayout(VStackLayout(alignment: .trailing)) : AnyLayout(HStackLayout())
    }

    private func passwordInput(_ title: String, text: Binding<String>, field: Field) -> some View {
        HStack(spacing: 6) {
            // The native secure control retains its own Caps Lock indicator.
            SecureField(title, text: text)
                .appleTouchTarget()
                .accessibilityIdentifier(field == .password ? "master.password" : "master.confirmation")
                .textFieldStyle(.plain)
                .focused($focused, equals: field)
                .onSubmit(submit)
            #if os(macOS)
            if focused == field, let source = keyboard.current, source.language != "EN" {
                Text(source.language)
                    .font(.caption.monospaced().weight(.medium))
                    .foregroundStyle(.secondary)
                    .fixedSize()
                    .help(source.name)
                    .accessibilityLabel(source.name)
            }
            #endif
        }
        .padding(.horizontal, 7)
        .padding(.vertical, 4)
        .background(Color.zannFieldBackground, in: RoundedRectangle(cornerRadius: 5))
        .overlay {
            RoundedRectangle(cornerRadius: 5)
                .strokeBorder(Color.zannSeparator)
                .allowsHitTesting(false)
        }
        .overlay {
            if focused == field {
                RoundedRectangle(cornerRadius: 6)
                    .stroke(Color.zannFocus.opacity(0.7), lineWidth: 3)
                    .padding(-1)
                    .allowsHitTesting(false)
            }
        }
    }

    private func submit() {
        guard canSubmit else { return }
        let password = password
        Task { await model.submit(password: password, mode: mode) }
    }
}
