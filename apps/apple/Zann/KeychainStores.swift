import Foundation
import Security
import ZannCoreKit

/// Keeps the device wrapping key that arms remembered unlock. Touch ID
/// (`SecAccessControl`, #146) is not wired yet, so the key is guarded only by
/// the login keychain and biometrics are reported as unavailable.
final class KeychainKeystore: PlatformKeystore {
    private let service: String
    private let account = "device-wrapping-key"

    init(service: String) {
        self.service = service
    }

    func status() -> PlatformKeystoreStatus {
        PlatformKeystoreStatus(supported: true, biometricsAvailable: false, reason: nil, message: nil)
    }

    func storeDwk(dwk: Data) throws {
        try Keychain.put(
            service: service, account: account, data: dwk,
            accessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        )
    }

    func loadDwk() throws -> Data? {
        try Keychain.get(service: service, account: account)
    }

    func deleteDwk() throws {
        try Keychain.delete(service: service, account: account)
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
private enum Keychain {
    static func put(service: String, account: String, data: Data, accessible: CFString) throws {
        let query = itemQuery(service: service, account: account)
        let attributes: [CFString: Any] = [kSecValueData: data, kSecAttrAccessible: accessible]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            let added = query.merging(attributes) { _, new in new }
            try check(SecItemAdd(added as CFDictionary, nil))
        } else {
            try check(status)
        }
    }

    static func get(service: String, account: String) throws -> Data? {
        var query = itemQuery(service: service, account: account)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
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

    static func delete(service: String, account: String) throws {
        let status = SecItemDelete(itemQuery(service: service, account: account) as CFDictionary)
        if status != errSecItemNotFound {
            try check(status)
        }
    }

    private static func itemQuery(service: String, account: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
    }

    private static func check(_ status: OSStatus) throws {
        switch status {
        case errSecSuccess:
            return
        case errSecUserCanceled:
            throw PlatformStoreError.Cancelled
        default:
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            throw PlatformStoreError.Unavailable(message: message)
        }
    }
}
