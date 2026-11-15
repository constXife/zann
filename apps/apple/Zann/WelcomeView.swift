import SwiftUI

struct WelcomeView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(spacing: 16) {
            WelcomeIntro()
            Button { model.startConnecting() } label: {
                Text(model.strings("wizard.connect")).appleTouchTarget()
            }
                .controlSize(.large)
                .accessibilityIdentifier("onboarding.connect")
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
