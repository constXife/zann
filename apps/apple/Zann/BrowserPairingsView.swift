import SwiftUI
import ZannCoreKit

/// Native display only; code admission, pairing and revocation belong to Rust.
struct BrowserPairingsView: View {
    let core: CoreFacade?
    let strings: Strings
    let preferences: DevicePreferencesFfi
    @Environment(\.copyFeedbackDuration) private var copyFeedbackDuration
    @State private var settings: BrowserPairingSettingsFfi?
    @State private var code: BrowserPairingCodeFfi?
    @State private var copiedCodeID: String?
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        Section(strings("browser.title")) {
            Text(strings("browser.codeHint")).font(.caption).foregroundStyle(.secondary)
            Button(strings("browser.connect")) { Task { await begin() } }
                .disabled(busy || core == nil)
            if let code {
                LabeledContent(strings("browser.code")) {
                    Text(code.value)
                        .font(.title.monospaced()).privacySensitive()
                    Button(strings(copiedCodeID == code.id ? "common.copied" : "browser.copyCode")) {
                        Task { await copyCode(id: code.id) }
                    }
                    .disabled(busy)
                }
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
        .task(id: copiedCodeID) {
            guard copiedCodeID != nil else { return }
            do { try await Task.sleep(for: copyFeedbackDuration) }
            catch is CancellationError { return }
            catch { self.error = describe(error); return }
            copiedCodeID = nil
        }
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

    @discardableResult
    @MainActor private func refresh() async -> BrowserPairingSettingsFfi? {
        guard let core, !busy else { return nil }
        busy = true
        let result = await BlockingCore.run {
            Result { try core.browserPairings() }
        }
        busy = false
        switch result {
        case .success(let value):
            settings = value
            if value.activeCodeId != code?.id { code = nil }
            error = nil
            return value
        case .failure(let failure):
            error = describe(failure)
            return nil
        }
    }

    @MainActor private func copyCode(id: String) async {
        guard let current = await refresh(), current.activeCodeId == id,
              let code, code.id == id else { return }
        Clipboard.copy(code.value, clearAfter: preferences.clipboardClearSeconds,
                       onlyIfUnchanged: preferences.clipboardClearIfUnchanged)
        copiedCodeID = id
    }

    @MainActor private func begin() async {
        guard let core, !busy else { return }
        busy = true
        code = nil
        let result = await BlockingCore.run {
            Result { try core.browserBeginPairing() }
        }
        busy = false
        switch result {
        case .success(let value): code = value; error = nil
        case .failure(let failure): error = describe(failure)
        }
    }

    @MainActor private func revoke(_ key: String) async {
        guard let core, !busy else { return }
        busy = true
        let result = await BlockingCore.run {
            Result { try core.browserRevoke(publicKey: key) }
        }
        busy = false
        switch result {
        case .success: await refresh()
        case .failure(let failure): error = describe(failure)
        }
    }
}
