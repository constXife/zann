import SwiftUI

/// Shared first screen copy; account setup actions are supplied by each shell.
struct WelcomeIntro: View {
    var body: some View {
        Text("Zann")
            .font(.largeTitle.bold())
            .accessibilityIdentifier("onboarding.title")
        Text("Connect to your Zann server. Your encrypted vault stays available offline.")
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
    }
}
