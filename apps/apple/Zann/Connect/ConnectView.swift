import SwiftUI
import ZannCoreKit

/// The connect steps COSMIC also walks through: server, a changed
/// fingerprint, the sign-in method, then the password form or the browser.
struct ConnectView: View {
    @ObservedObject var connect: ConnectModel
    @EnvironmentObject private var app: AppModel

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
            }
            HStack {
                Button(app.strings("wizard.back")) {
                    password = ""
                    if !connect.back() { app.leaveConnecting() }
                }
                .keyboardShortcut(.cancelAction)
                Spacer()
                if connect.busy {
                    ProgressView().controlSize(.small)
                }
                primary
            }
        }
        .textFieldStyle(.roundedBorder)
        .padding(32)
        .frame(maxWidth: 420)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear { focused = true }
    }

    @ViewBuilder private var step: some View {
        switch connect.stage {
        case .server:
            TextField(app.strings("auth.serverUrl"), text: $connect.url, prompt: Text("https://zann.example.com"))
                .focused($focused)
                .onSubmit(probe)
                .disableAutocorrection(true)
        case .fingerprint(let old, let new):
            Text(app.strings("wizard.fingerprintWarning"))
            fingerprint(app.strings("wizard.oldFingerprint"), old)
            fingerprint(app.strings("wizard.newFingerprint"), new)
        case .methods:
            Text(app.strings("auth.selectMethod"))
            ForEach(connect.methods, id: \.self) { method in
                switch method {
                case .password:
                    Button(app.strings("auth.emailPassword")) { connect.choosePassword() }
                        .frame(maxWidth: .infinity)
                case .oidc:
                    Button(app.strings("auth.oidc")) {
                        Task { await connect.signInWithBrowser() }
                    }
                    .frame(maxWidth: .infinity)
                case .serviceAccount:
                    EmptyView()
                }
            }
            .disabled(connect.busy)
        case .password(let register):
            TextField(app.strings("auth.email"), text: $connect.email, prompt: Text("you@example.com"))
                .textContentType(.username)
                .disableAutocorrection(true)
            if register {
                TextField(app.strings("auth.fullName"), text: $connect.fullName)
            }
            SecureField(app.strings("auth.password"), text: $password)
                .textContentType(.password)
                .onSubmit(submitPassword)
            if connect.registrationAvailable {
                Button(app.strings(register ? "auth.haveAccount" : "auth.noAccount")) {
                    connect.setRegistering(!register)
                }
                .buttonStyle(.link)
                .disabled(connect.busy)
            }
        case .complete, .closed:
            EmptyView()
        case .browser:
            Text(app.strings("wizard.oidcHint"))
            Button(app.strings("wizard.oidcReopen")) { connect.reopenBrowser() }
                .buttonStyle(.link)
            Button(app.strings("auth.copyLink")) { connect.copyBrowserLink() }
                .buttonStyle(.link)
        }
    }

    @ViewBuilder private var primary: some View {
        switch connect.stage {
        case .server:
            Button(app.strings("common.continue"), action: probe)
                .keyboardShortcut(.defaultAction)
                .disabled(connect.busy || connect.url.trimmingCharacters(in: .whitespaces).isEmpty)
        case .fingerprint:
            Button(app.strings("wizard.trustFingerprint"), role: .destructive) {
                Task { await connect.trustFingerprint() }
            }
            .disabled(connect.busy)
        case .password(let register):
            Button(app.strings(register ? "auth.signUp" : "auth.signIn"), action: submitPassword)
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
        guard connect.canSubmitPassword(password) else { return }
        let submitted = password
        password = ""
        Task { await connect.submitPassword(submitted) }
    }
}
