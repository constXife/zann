import SwiftUI
import ZannCoreKit

/// The core validates and commits the replacement; the form only confirms it.
struct UnlockPasswordSettings: View {
    let core: CoreFacade?
    let unlocked: Bool
    let strings: Strings
    @State private var current = ""
    @State private var replacement = ""
    @State private var confirmation = ""
    @State private var presenting = false
    @State private var saving = false
    @State private var message: String?

    var body: some View {
        Section(strings("unlock.passwordTitle")) {
            Button(strings("unlock.changePassword")) { presenting = true }
                .disabled(!unlocked || saving)
        }
        .sheet(isPresented: $presenting) { form }
        .onChange(of: unlocked) { _ in clear(); presenting = false }
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(strings("unlock.changePassword")).font(.title2.bold())
            Text(strings("unlock.changeHelp")).foregroundStyle(.secondary)
            SecureField(strings("unlock.currentPassword"), text: $current)
            SecureField(strings("unlock.newPassword"), text: $replacement)
            SecureField(strings("unlock.confirmPassword"), text: $confirmation)
            if !confirmation.isEmpty && replacement != confirmation {
                Text(strings("unlock.passwordMismatch")).foregroundStyle(.red)
            }
            if let message { Text(message).textSelection(.enabled) }
            HStack {
                Button(strings("common.cancel")) { clear(); presenting = false }.disabled(saving)
                Spacer()
                if saving { ProgressView().controlSize(.small) }
                Button(strings("unlock.changePassword")) { change() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!unlocked || saving || current.isEmpty || replacement.isEmpty || replacement != confirmation)
            }
        }
        .textFieldStyle(.roundedBorder)
        .padding(24)
        .frame(width: 420)
        .onDisappear { clear(); message = nil }
    }

    private func clear() { current = ""; replacement = ""; confirmation = "" }

    private func change() {
        guard let core else { return }
        let old = current
        let new = replacement
        clear()
        message = nil
        saving = true
        Task {
            defer { saving = false }
            do {
                try await Task.detached { try core.changeUnlockPassword(current: old, replacement: new) }.value
                message = strings("unlock.passwordChanged")
            } catch {
                message = strings.message(for: error)
            }
        }
    }
}
