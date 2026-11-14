import Foundation
import ZannCoreKit

extension AppModel {
    /// The database lives under Application Support in a directory named after
    /// the bundle, isolated from other native client containers. The Touch ID reason is
    /// set by `AppModel` once it knows the language.
    static func openDefaultCore() throws -> (core: CoreFacade, keystore: DeviceKeystore) {
        let keystore = KeychainKeystore(service: try Self.bundleID(), promptReason: "")
        let core = try createCore(
            dbPath: try Self.dataDirectory().appendingPathComponent("local.sqlite").path,
            keystore: keystore,
            secretStore: KeychainSecretStore()
        )
        try core.startBrowserService()
        return (core, keystore)
    }

    /// Beside the database, so one directory holds all of this app's state.
    static func defaultPreferencesFile() throws -> PreferencesFile {
        PreferencesFile(url: try dataDirectory().appendingPathComponent("preferences.json"))
    }

    private static func dataDirectory() throws -> URL {
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        )
        return support.appendingPathComponent(try bundleID(), isDirectory: true)
    }

    private static func bundleID() throws -> String {
        guard let bundleID = Bundle.main.bundleIdentifier else {
            throw CoreError.InvalidArgument("the app bundle has no identifier")
        }
        return bundleID
    }
}
