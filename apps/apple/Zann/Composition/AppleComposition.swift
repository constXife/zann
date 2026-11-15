import Foundation
import ZannCoreKit

/// Platform-neutral storage factory. Desktop services are started only by
/// the macOS composition after opening this exact core.
struct AppleComposition {
    let storage: AppleStorage
    let keystore: DeviceKeystore
    let secretStore: PlatformSecretStore

    func openCore() throws -> (core: CoreFacade, keystore: DeviceKeystore) {
        let core = try createCore(
            dbPath: storage.database.path,
            keystore: keystore,
            secretStore: secretStore
        )
        return (core, keystore)
    }
}
