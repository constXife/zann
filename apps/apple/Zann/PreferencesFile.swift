import Foundation
import ZannCoreKit

/// This shell's device preferences file. docs/Architecture.md lets a client
/// keep its private UI preferences in its own file; zann-ui-core owns the
/// stored form and the defaults, so this type only reads and replaces bytes.
struct PreferencesFile {
    let url: URL

    /// The stored preferences, or zann-ui-core's defaults before the first
    /// save. A file that does not parse is an error, never silently reset.
    func load() throws -> DevicePreferencesFfi {
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch let error as CocoaError where error.code == .fileReadNoSuchFile {
            return devicePreferencesDefault()
        }
        return try devicePreferencesFromJson(json: String(decoding: data, as: UTF8.self))
    }

    /// Replaces the file atomically with owner-only permissions.
    func save(_ preferences: DevicePreferencesFfi) throws {
        let manager = FileManager.default
        let directory = url.deletingLastPathComponent()
        try manager.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let temporary = directory.appendingPathComponent(".\(url.lastPathComponent).tmp")
        if manager.fileExists(atPath: temporary.path) {
            try manager.removeItem(at: temporary)
        }
        let data = Data(devicePreferencesToJson(preferences: preferences).utf8)
        guard manager.createFile(
            atPath: temporary.path, contents: data, attributes: [.posixPermissions: 0o600]
        ) else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: temporary.path])
        }
        _ = try manager.replaceItemAt(url, withItemAt: temporary)
    }
}
