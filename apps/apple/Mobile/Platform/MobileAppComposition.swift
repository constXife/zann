import UIKit
import ZannCoreKit

@MainActor
enum MobileAppComposition {
    static func makeModel(webAuthentication: WebAuthentication) -> AppModel {
        let identity = Result { try MobileTargetConfiguration.identity(bundle: .main) }
        let redirect = Result { try MobileTargetConfiguration.oidcRedirectURI(bundle: .main) }
        let composition = Result {
            let mobile = try MobileComposition(identity: identity.get()) {
                FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: $0)
            }
            return mobile.compose(keystore: { service, group in
                KeychainKeystore(service: service, scope: .accessGroup(group))
            }, secretStore: { KeychainSecretStore(scope: .accessGroup($0)) })
        }
        // A missing redirect is a configuration failure before opening core,
        // never a reason to use desktop loopback on a mobile device.
        let configured = Result { (try composition.get(), try redirect.get()) }
        return AppModel(opening: { try configured.get().0.openCore() }, preferences: {
            try configured.get().0.storage.preferences
        }, systemLanguage: Locale.current.identifier,
        browser: .system(redirectURI: redirect, authorize: { url, scheme, timeout in
            try await webAuthentication.authorize(url: url, scheme: scheme, timeoutMs: timeout)
        }, cancel: { webAuthentication.cancel() }))
    }
}
