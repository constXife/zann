import Foundation
import ZannCoreKit

/// Target configuration, shared by the containing app and future provider.
/// Values come from target configuration, never the current process's bundle ID.
struct MobileIdentity: Equatable {
    let appGroup: String
    let vaultService: String
    let vaultAccessGroup: String
    let tokenAccessGroup: String

    init(appGroup: String, vaultService: String, vaultAccessGroup: String, tokenAccessGroup: String) throws {
        let values = [appGroup, vaultService, vaultAccessGroup, tokenAccessGroup]
        guard values.allSatisfy({ !$0.isEmpty && !$0.contains(where: { $0.isWhitespace }) && !$0.contains("$(") }),
              appGroup.hasPrefix("group."), appGroup.count > "group.".count,
              vaultAccessGroup != tokenAccessGroup, tokenAccessGroup != appGroup else {
            throw AppleCompositionError.invalidMobileIdentity
        }
        self.appGroup = appGroup
        self.vaultService = vaultService
        self.vaultAccessGroup = vaultAccessGroup
        self.tokenAccessGroup = tokenAccessGroup
    }
}

/// Resolves the shared mobile root without opening Keychain, SQLite or IPC.
/// Mobile OS adapters receive these exact namespaces; provider
/// unlock/revocation semantics belong to #277.
struct MobileComposition {
    let identity: MobileIdentity
    let storage: AppleStorage

    init(identity: MobileIdentity, containerURL: (String) -> URL?) throws {
        guard let container = containerURL(identity.appGroup) else {
            throw AppleCompositionError.appGroupUnavailable(identity.appGroup)
        }
        _ = try AppleStorage(directory: container)
        self.identity = identity
        storage = try AppleStorage(directory: container
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("Zann", isDirectory: true))
    }

    /// Explicit factories prevent either adapter from selecting a default
    /// namespace based on whichever app/extension process happens to run.
    func compose(
        keystore: (_ service: String, _ accessGroup: String) throws -> DeviceKeystore,
        secretStore: (_ accessGroup: String) throws -> PlatformSecretStore
    ) rethrows -> AppleComposition {
        try AppleComposition(
            storage: storage,
            keystore: keystore(identity.vaultService, identity.vaultAccessGroup),
            secretStore: secretStore(identity.tokenAccessGroup)
        )
    }
}
