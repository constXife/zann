import Foundation
import LocalAuthentication
import Security
import ZannCoreKit

/// The keystore the app composes the core with: the core's port, plus the
/// wording of the Touch ID sheet, which follows the app's language.
protocol DeviceKeystore: PlatformKeystore {
    func setPromptReason(_ reason: String)
}

/// Keeps the device wrapping key that arms remembered unlock (#146). The key
/// sits in the data protection keychain under a `.biometryCurrentSet` access
/// control, so macOS releases it only after Touch ID and drops it when the
/// enrolled fingers change; a prompt gates the key itself, not just control
/// flow. That keychain needs a team-signed build (Signing.xcconfig); an
/// ad-hoc build reports the keystore unsupported rather than storing the key
/// anywhere weaker.
final class KeychainKeystore: DeviceKeystore {
    private let service: String
    private let account = "device-wrapping-key"
    private let lock = NSLock()
    private var promptReason: String

    init(service: String, promptReason: String) {
        self.service = service
        self.promptReason = promptReason
    }

    /// The Touch ID sheet's reason, in the current language.
    func setPromptReason(_ reason: String) {
        lock.withLock { promptReason = reason }
    }

    /// Never prompts: it reads this process's own entitlements, and
    /// LocalAuthentication only evaluates.
    func status() -> PlatformKeystoreStatus {
        guard Keychain.dataProtectionAvailable() else {
            return PlatformKeystoreStatus(
                supported: false, biometricsAvailable: false, reason: .unavailable,
                message: "this build is not signed with an Apple team"
            )
        }
        var error: NSError?
        if LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            return PlatformKeystoreStatus(
                supported: true, biometricsAvailable: true, reason: nil, message: nil
            )
        }
        let reason: PlatformKeystoreStatusReason
        switch error.flatMap({ LAError.Code(rawValue: $0.code) }) {
        case .biometryNotEnrolled: reason = .notEnrolled
        case .biometryLockout: reason = .lockedOut
        default: reason = .unavailable
        }
        return PlatformKeystoreStatus(
            supported: true, biometricsAvailable: false, reason: reason,
            message: error?.localizedDescription
        )
    }

    func storeDwk(dwk: Data) throws {
        let current = status()
        guard current.supported else { throw PlatformStoreError.Unsupported }
        guard current.biometricsAvailable else {
            throw PlatformStoreError.Unavailable(message: current.message ?? "Touch ID is not available")
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &error
        ) else {
            let message = error.map { CFErrorCopyDescription($0.takeRetainedValue()) as String }
            throw PlatformStoreError.Unavailable(message: message ?? "access control unavailable")
        }
        // An access control cannot be updated in place: replace the item.
        try deleteDwk()
        try Keychain.add(
            service: service, account: account, data: dwk,
            protection: [kSecAttrAccessControl: access], dataProtection: true
        )
    }

    /// Presents Touch ID; the core calls this off the main thread.
    func loadDwk() throws -> Data? {
        let context = LAContext()
        context.localizedReason = lock.withLock { promptReason }
        return try Keychain.get(
            service: service, account: account, dataProtection: true,
            extra: [kSecUseAuthenticationContext: context]
        )
    }

    func deleteDwk() throws {
        try Keychain.delete(service: service, account: account, dataProtection: true)
    }
}

/// Session tokens under the service and account names the core chooses. The
/// core calls this from background threads, so it must never need user
/// presence.
final class KeychainSecretStore: PlatformSecretStore {
    func put(service: String, account: String, secret: String) throws {
        try Keychain.put(
            service: service, account: account, data: Data(secret.utf8),
            accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        )
    }

    func get(service: String, account: String) throws -> String? {
        try Keychain.get(service: service, account: account)
            .map { String(decoding: $0, as: UTF8.self) }
    }

    func delete(service: String, account: String) throws {
        try Keychain.delete(service: service, account: account)
    }
}

/// Generic-password items: `put` replaces, `get` maps a missing item to `nil`
/// and `delete` treats a missing item as success, as the port contracts ask.
/// `dataProtection` selects the data protection keychain, which access
/// controls need; a build without its entitlement gets `Unsupported`.
private enum Keychain {
    static func put(service: String, account: String, data: Data, accessible: CFString) throws {
        let query = itemQuery(service: service, account: account, dataProtection: false)
        let attributes: [CFString: Any] = [kSecValueData: data, kSecAttrAccessible: accessible]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            try add(
                service: service, account: account, data: data,
                protection: [kSecAttrAccessible: accessible], dataProtection: false
            )
        } else {
            try check(status)
        }
    }

    static func add(
        service: String, account: String, data: Data,
        protection: [CFString: Any], dataProtection: Bool
    ) throws {
        var query = itemQuery(service: service, account: account, dataProtection: dataProtection)
        query[kSecValueData] = data
        query.merge(protection) { _, new in new }
        try check(SecItemAdd(query as CFDictionary, nil))
    }

    static func get(
        service: String, account: String, dataProtection: Bool = false,
        extra: [CFString: Any] = [:]
    ) throws -> Data? {
        var query = itemQuery(service: service, account: account, dataProtection: dataProtection)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        query.merge(extra) { _, new in new }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        try check(status)
        guard let data = result as? Data else {
            throw PlatformStoreError.Unavailable(message: "keychain item holds no data")
        }
        return data
    }

    static func delete(service: String, account: String, dataProtection: Bool = false) throws {
        let query = itemQuery(service: service, account: account, dataProtection: dataProtection)
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecItemNotFound {
            try check(status)
        }
    }

    /// Whether this build carries the keychain access group the data
    /// protection keychain needs. Read from the process's own signature: a
    /// keychain query for a missing item answers "not found" before it checks
    /// the entitlement, so it cannot tell.
    static func dataProtectionAvailable() -> Bool {
        guard let task = SecTaskCreateFromSelf(nil) else { return false }
        let groups = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil)
        return (groups as? [String])?.isEmpty == false
    }

    private static func itemQuery(
        service: String, account: String, dataProtection: Bool
    ) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        if dataProtection {
            query[kSecUseDataProtectionKeychain] = true
        }
        return query
    }

    private static func check(_ status: OSStatus) throws {
        switch status {
        case errSecSuccess:
            return
        case errSecUserCanceled:
            throw PlatformStoreError.Cancelled
        case errSecMissingEntitlement:
            throw PlatformStoreError.Unsupported
        default:
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            throw PlatformStoreError.Unavailable(message: message)
        }
    }
}
