import SwiftUI

struct MobileRootView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var lifecycle: MobileLifecycle

    var body: some View {
        screen
            .id(lifecycle.visibilityEpoch)
            .environmentObject(model)
            .background(WindowAttachment { lifecycle.attach($0) })
            .simultaneousGesture(DragGesture(minimumDistance: 0).onChanged { _ in model.noteActivity() })
    }

    @ViewBuilder private var screen: some View {
        switch model.screen {
        case .welcome: WelcomeView()
        case .accounts:
            if let recovery = model.recovery { RecoveryView(recovery: recovery) }
        case .connect:
            if let connect = model.connect {
                ScrollView { ConnectView(connect: connect) }.scrollDismissesKeyboard(.interactively)
            }
        case .master(let mode):
            ScrollView { MasterPasswordView(mode: mode) }.scrollDismissesKeyboard(.interactively)
        case .vault:
            if let vault = model.vault { MobileVaultView(vault: vault) }
        case .failed(let error):
            Text(error).textSelection(.enabled).padding(32)
        }
    }
}
