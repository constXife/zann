import Foundation
import Security
import ZannCoreKit

enum KeychainScope {
    #if os(macOS)
    case macOS
    #endif
    case accessGroup(String)

    var protectTokens: Bool {
        switch self {
        #if os(macOS)
        case .macOS: return false
        #endif
        case .accessGroup: return true
        }
    }
}

/// Generic-password items: `put` replaces, `get` maps a missing item to `nil`
/// and `delete` treats a missing item as success, as the port contracts ask.
/// `dataProtection` selects the data protection keychain, which access
/// controls need; a build without its entitlement gets `Unsupported`.
enum Keychain {
    static func put(service: String, account: String, data: Data, accessible: CFString, scope: KeychainScope) throws {
        let query = itemQuery(service: service, account: account, dataProtection: scope.protectTokens, scope: scope)
        let attributes: [CFString: Any] = [kSecValueData: data, kSecAttrAccessible: accessible]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            try add(
                service: service, account: account, data: data,
                protection: [kSecAttrAccessible: accessible], dataProtection: scope.protectTokens, scope: scope
            )
        } else {
            try check(status)
        }
    }

    static func add(
        service: String, account: String, data: Data,
        protection: [CFString: Any], dataProtection: Bool, scope: KeychainScope
    ) throws {
        var query = itemQuery(service: service, account: account, dataProtection: dataProtection || scope.protectTokens, scope: scope)
        query[kSecValueData] = data
        query.merge(protection) { _, new in new }
        try check(SecItemAdd(query as CFDictionary, nil))
    }

    static func get(
        service: String, account: String, dataProtection: Bool = false, scope: KeychainScope,
        extra: [CFString: Any] = [:]
    ) throws -> Data? {
        var query = itemQuery(service: service, account: account, dataProtection: dataProtection || scope.protectTokens, scope: scope)
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

    static func delete(service: String, account: String, dataProtection: Bool = false, scope: KeychainScope) throws {
        let query = itemQuery(service: service, account: account, dataProtection: dataProtection || scope.protectTokens, scope: scope)
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecItemNotFound {
            try check(status)
        }
    }

    /// Whether this build carries the keychain access group the data
    /// protection keychain needs. Read from the process's own signature: a
    /// keychain query for a missing item answers "not found" before it checks
    /// the entitlement, so it cannot tell.
    static func dataProtectionAvailable(scope: KeychainScope) -> Bool {
        #if os(macOS)
        guard let task = SecTaskCreateFromSelf(nil) else { return false }
        let groups = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil)
        guard let groups = groups as? [String] else { return false }
        switch scope {
        case .macOS: return !groups.isEmpty
        case .accessGroup(let group): return groups.contains(group)
        }
        #else
        // iOS provides the data-protection Keychain. Each actual operation
        // still supplies its access group and the OS enforces entitlements.
        return true
        #endif
    }

    static func itemQuery(
        service: String, account: String, dataProtection: Bool, scope: KeychainScope
    ) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
        if case .accessGroup(let group) = scope { query[kSecAttrAccessGroup] = group }
        if dataProtection || scope.protectTokens {
            query[kSecUseDataProtectionKeychain] = true
        }
        return query
    }

    static func check(_ status: OSStatus) throws {
        switch status {
        case errSecSuccess:
            return
        case errSecUserCanceled:
            throw PlatformStoreError.Cancelled
        case errSecMissingEntitlement:
            throw PlatformStoreError.Unsupported
        default:
            let message = SecCopyErrorMessageString(status, nil) as String?
            throw PlatformStoreError.Unavailable(message: "Keychain OSStatus \(status): \(message ?? "no system description")")
        }
    }
}
