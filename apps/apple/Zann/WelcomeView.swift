import SwiftUI

struct WelcomeView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(spacing: 16) {
            Text("Zann").font(.largeTitle.bold())
            Text("Keep a vault on this Mac, encrypted with your master password.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Create a Local Vault") { model.startCreatingVault() }
                .keyboardShortcut(.defaultAction)
                .controlSize(.large)
            Button(model.strings("wizard.connect")) { model.startConnecting() }
                .controlSize(.large)
            if let error = model.error {
                Text(error).foregroundStyle(.red).textSelection(.enabled)
            }
        }
        .padding(32)
        .frame(maxWidth: 420)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
