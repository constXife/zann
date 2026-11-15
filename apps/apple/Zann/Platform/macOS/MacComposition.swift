#if os(macOS)
import AppKit
import ZannCoreKit

/// macOS-only composition: the existing Keychain namespaces and desktop IPC
/// remain here, outside shared models and mobile storage composition.
enum MacComposition {
    @MainActor
    static func makeModel() -> AppModel {
        // Resolve once, including on failure. Preferences and the core must
        // never independently select different application roots.
        let composition = Result {
            guard let bundleIdentifier = Bundle.main.bundleIdentifier else {
                throw AppleCompositionError.missingBundleIdentifier
            }
            let support = try FileManager.default.url(
                for: .applicationSupportDirectory, in: .userDomainMask,
                appropriateFor: nil, create: true
            )
            let storage = try AppleStorage.macOS(
                applicationSupport: support, bundleIdentifier: bundleIdentifier
            )
            return AppleComposition(
                storage: storage,
                keystore: KeychainKeystore(service: bundleIdentifier, scope: .macOS),
                secretStore: KeychainSecretStore(scope: .macOS)
            )
        }
        return AppModel(opening: {
            let opened = try composition.get().openCore()
            try opened.core.startBrowserService()
            return opened
        }, preferences: {
            try composition.get().storage.preferences
        }, systemLanguage: Locale.preferredLanguages.first ?? Locale.current.identifier,
        browser: .loopback(open: { NSWorkspace.shared.open($0) }))
    }
}
#endif
