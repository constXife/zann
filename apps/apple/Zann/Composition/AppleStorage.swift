import Foundation

/// The shell selects one root; the Rust native opener canonicalizes it and
/// derives Config v2, locks and snapshots from the database's parent.
struct AppleStorage: Equatable {
    let directory: URL

    var database: URL { directory.appendingPathComponent("local.sqlite") }
    var preferences: PreferencesFile {
        PreferencesFile(url: directory.appendingPathComponent("preferences.json"))
    }

    init(directory: URL) throws {
        guard directory.isFileURL, directory.host == nil || directory.host == "",
              directory.path.hasPrefix("/"),
              !directory.pathComponents.contains(".."),
              directory.query == nil, directory.fragment == nil else {
            throw AppleCompositionError.invalidStorageDirectory
        }
        self.directory = directory
    }

    /// Preserve the existing macOS Application Support/<bundle-id> root.
    static func macOS(applicationSupport: URL, bundleIdentifier: String?) throws -> Self {
        guard let bundleIdentifier, !bundleIdentifier.isEmpty,
              !bundleIdentifier.contains("/"), bundleIdentifier != ".", bundleIdentifier != ".." else {
            throw AppleCompositionError.missingBundleIdentifier
        }
        _ = try Self(directory: applicationSupport)
        return try Self(directory: applicationSupport.appendingPathComponent(bundleIdentifier, isDirectory: true))
    }
}

enum AppleCompositionError: Error, Equatable, LocalizedError {
    case invalidStorageDirectory
    case missingBundleIdentifier
    case invalidMobileIdentity
    case appGroupUnavailable(String)
    case missingOIDCRedirectURI

    var errorDescription: String? {
        switch self {
        case .invalidStorageDirectory:
            return "The application storage directory must be an absolute local file URL without parent traversal."
        case .missingBundleIdentifier:
            return "The app bundle has no valid identifier."
        case .invalidMobileIdentity:
            return "Mobile storage requires an App Group, a vault service and distinct vault and token Keychain access groups."
        case .appGroupUnavailable(let identifier):
            return "The entitled App Group container is unavailable: \(identifier)."
        case .missingOIDCRedirectURI:
            return "The mobile sign-in callback is not configured."
        }
    }
}
