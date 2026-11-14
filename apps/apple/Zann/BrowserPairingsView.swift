import SwiftUI
import ZannCoreKit

/// Native display only; code admission, pairing and revocation belong to Rust.
struct BrowserPairingsView: View {
    let core: CoreFacade?
    let strings: Strings
    @State private var settings: BrowserPairingSettingsFfi?
    @State private var code: BrowserPairingCodeFfi?
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        Section(strings("browser.title")) {
            Text(strings("browser.codeHint")).font(.caption).foregroundStyle(.secondary)
            Button(strings("browser.connect")) { Task { await begin() } }
                .disabled(busy || core == nil)
            if let code {
                Text("\(strings("browser.code")): \(code.value)")
                    .font(.title.monospaced()).privacySensitive()
            }
            Button(strings("browser.refresh")) { Task { await refresh() } }
                .disabled(busy || core == nil)
            if let settings {
                ForEach(settings.paired, id: \.publicKey) { pairing in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(pairing.name)
                        Text(pairing.publicKey).font(.caption.monospaced()).textSelection(.enabled)
                        Button(strings("browser.revoke"), role: .destructive) {
                            Task { await revoke(pairing.publicKey) }
                        }
                        .disabled(busy)
                    }
                }
            }
            if let error { Text(error).foregroundStyle(.red) }
        }
        .task { await refresh() }
        .task(id: code?.id) {
            guard let current = code else { return }
            // Native settings decides whether the code is still active. Poll
            // only during pairing to remove consumed/expired codes and show the
            // new browser without a manual refresh.
            for _ in 0..<current.expiresInSeconds {
                do { try await Task.sleep(for: .seconds(1)) }
                catch is CancellationError { return }
                catch { self.error = describe(error); return }
                await refresh()
                if code?.id != current.id { return }
            }
            code = nil
        }
        .onDisappear { code = nil }
    }

    @MainActor private func refresh() async {
        guard let core, !busy else { return }
        busy = true
        let result = await Task.detached(priority: .userInitiated) {
            Result { try core.browserPairings() }
        }.value
        busy = false
        switch result {
        case .success(let value):
            settings = value
            if value.activeCodeId != code?.id { code = nil }
            error = nil
        case .failure(let failure): error = describe(failure)
        }
    }

    @MainActor private func begin() async {
        guard let core, !busy else { return }
        busy = true
        code = nil
        let result = await Task.detached(priority: .userInitiated) {
            Result { try core.browserBeginPairing() }
        }.value
        busy = false
        switch result {
        case .success(let value): code = value; error = nil
        case .failure(let failure): error = describe(failure)
        }
    }

    @MainActor private func revoke(_ key: String) async {
        guard let core, !busy else { return }
        busy = true
        let result = await Task.detached(priority: .userInitiated) {
            Result { try core.browserRevoke(publicKey: key) }
        }.value
        busy = false
        switch result {
        case .success: await refresh()
        case .failure(let failure): error = describe(failure)
        }
    }
}
