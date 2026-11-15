import Foundation

/// Xcode expands these four values from one target configuration into both
/// Info.plist and signing entitlements; no process-bundle-derived identities.
enum MobileTargetConfiguration {
    static func oidcRedirectURI(bundle: Bundle) throws -> String {
        guard let uri = bundle.object(forInfoDictionaryKey: "ZannOIDCRedirectURI") as? String,
              !uri.isEmpty, !uri.contains("$(") else { throw AppleCompositionError.missingOIDCRedirectURI }
        return uri
    }
    static func identity(bundle: Bundle) throws -> MobileIdentity {
        guard let appGroup = bundle.object(forInfoDictionaryKey: "ZannAppGroup") as? String,
              let service = bundle.object(forInfoDictionaryKey: "ZannVaultKeychainService") as? String,
              let vaultGroup = bundle.object(forInfoDictionaryKey: "ZannVaultKeychainAccessGroup") as? String,
              let tokenGroup = bundle.object(forInfoDictionaryKey: "ZannTokenKeychainAccessGroup") as? String else {
            throw AppleCompositionError.invalidMobileIdentity
        }
        return try MobileIdentity(
            appGroup: appGroup, vaultService: service,
            vaultAccessGroup: vaultGroup, tokenAccessGroup: tokenGroup
        )
    }
}
