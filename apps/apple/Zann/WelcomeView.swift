import SwiftUI

struct WelcomeView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(spacing: 16) {
            Text("Zann").font(.largeTitle.bold())
            Text(model.strings("wizard.welcomeSubtitle"))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button(model.strings("wizard.connect")) { model.startConnecting() }
                .controlSize(.large)
            Button(model.strings("recovery.title")) { model.showAccountRecovery() }
            if let error = model.error {
                Text(error).foregroundStyle(.red).textSelection(.enabled)
            }
        }
        .padding(32)
        .frame(maxWidth: 420)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
