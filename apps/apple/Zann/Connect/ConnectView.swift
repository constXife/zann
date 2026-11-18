import SwiftUI
import ZannCoreKit

/// The connect steps COSMIC also walks through: server, a changed
/// fingerprint, the sign-in method, then the password form or the browser.
struct ConnectView: View {
    @ObservedObject var connect: ConnectModel
    @EnvironmentObject private var app: AppModel

    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.dynamicTypeSize) private var textSize
    @State private var password = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(app.strings("wizard.connectTitle")).font(.title2.bold())
            if let name = connect.serverName, connect.stage != .server {
                Text(name).foregroundStyle(.secondary)
            }
            step
            if let error = connect.error {
                Text(error).foregroundStyle(.red).textSelection(.enabled)
                    .accessibilityIdentifier("connect.error")
            }
            actionsLayout {
                Button {
                    password = ""
                    if !connect.back() { app.leaveConnecting() }
                } label: { Text(app.strings("wizard.back")).appleTouchTarget() }
                .keyboardShortcut(.cancelAction)
                Spacer()
                if connect.busy {
                    ProgressView().controlSize(.small)
                }
                primary
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
        .onAppear { focused = true }
        .onChange(of: scenePhase) { if $0 != .active { password = "" } }
    }

    private var actionsLayout: AnyLayout {
        textSize.isAccessibilitySize ? AnyLayout(VStackLayout(alignment: .trailing)) : AnyLayout(HStackLayout())
    }

    @ViewBuilder private var step: some View {
        switch connect.stage {
        case .server:
            TextField(app.strings("auth.serverUrl"), text: $connect.url, prompt: Text("https://zann.example.com"))
                .accessibilityIdentifier("connect.server")
                .appleTouchTarget()
                .focused($focused)
                .onSubmit(probe)
                .disableAutocorrection(true)
                #if os(iOS)
                .textInputAutocapitalization(.never)
                .keyboardType(.URL)
                #endif
        case .fingerprint(let old, let new):
            Text(app.strings("wizard.fingerprintWarning"))
            fingerprint(app.strings("wizard.oldFingerprint"), old)
            fingerprint(app.strings("wizard.newFingerprint"), new)
        case .methods:
            Text(app.strings("auth.selectMethod"))
            ForEach(connect.methods, id: \.self) { method in
                switch method {
                case .password:
                    Button { connect.choosePassword() } label: {
                        Text(app.strings("auth.emailPassword")).frame(maxWidth: .infinity).appleTouchTarget()
                    }
                    .accessibilityIdentifier("connect.method.password")
                case .oidc:
                    Button {
                        Task { await connect.signInWithBrowser() }
                    } label: { Text(app.strings("auth.oidc")).frame(maxWidth: .infinity).appleTouchTarget() }
                    .accessibilityIdentifier("connect.method.oidc")
                case .serviceAccount, .passkey:
                    EmptyView()
                }
            }
            .disabled(connect.busy)
        case .password(let register):
            TextField(app.strings("auth.email"), text: $connect.email, prompt: Text("you@example.com"))
                .appleTouchTarget()
                .textContentType(.username)
                .disableAutocorrection(true)
                #if os(iOS)
                .textInputAutocapitalization(.never)
                .keyboardType(.emailAddress)
                #endif
            if register {
                TextField(app.strings("auth.fullName"), text: $connect.fullName)
            }
            SecureField(app.strings("auth.password"), text: $password)
                .accessibilityIdentifier("connect.password")
                .appleTouchTarget()
                .textContentType(.password)
                .onSubmit(submitPassword)
            if connect.registrationAvailable {
                Button {
                    connect.setRegistering(!register)
                } label: { Text(app.strings(register ? "auth.haveAccount" : "auth.noAccount")).appleTouchTarget() }
                .buttonStyle(.borderless)
                .disabled(connect.busy)
            }
        case .complete, .closed:
            EmptyView()
        case .browser:
            Text(app.strings("wizard.oidcHint")).accessibilityIdentifier("connect.browser")
            if connect.canReopenBrowser {
                Button(app.strings("wizard.oidcReopen")) { connect.reopenBrowser() }.buttonStyle(.borderless)
                Button(app.strings("auth.copyLink")) { connect.copyBrowserLink() }.buttonStyle(.borderless)
            } else if !connect.busy {
                Button { Task { await connect.signInWithBrowser() } } label: {
                    Text(app.strings("common.retry")).appleTouchTarget()
                }
            }
        }
    }

    @ViewBuilder private var primary: some View {
        switch connect.stage {
        case .server:
            Button(action: probe) { Text(app.strings("common.continue")).appleTouchTarget() }
                .accessibilityIdentifier("connect.continue")
                .keyboardShortcut(.defaultAction)
                .disabled(connect.busy || connect.url.trimmingCharacters(in: .whitespaces).isEmpty)
        case .fingerprint:
            Button(role: .destructive) {
                Task { await connect.trustFingerprint() }
            } label: { Text(app.strings("wizard.trustFingerprint")).appleTouchTarget() }
            .disabled(connect.busy)
        case .password(let register):
            Button(action: submitPassword) {
                Text(app.strings(register ? "auth.signUp" : "auth.signIn")).appleTouchTarget()
            }
                .keyboardShortcut(.defaultAction)
                .disabled(!connect.canSubmitPassword(password))
        case .methods, .browser, .complete, .closed:
            EmptyView()
        }
    }

    private func fingerprint(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.body.monospaced()).textSelection(.enabled)
        }
    }

    private func probe() {
        Task { await connect.probe() }
    }

    private func submitPassword() {
        let password = password
        Task {
            await connect.submitPassword(password)
            self.password = ""
        }
    }
}
