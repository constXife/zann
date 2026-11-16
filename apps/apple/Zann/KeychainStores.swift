import Foundation
import LocalAuthentication
import Security
import ZannCoreKit

/// Keeps the device wrapping key that arms remembered unlock (#146). The key
/// sits in the data protection keychain under a `.biometryCurrentSet` access
/// control, so macOS releases it only after Touch ID and drops it when the
/// enrolled fingers change; a prompt gates the key itself, not just control
/// flow. That keychain needs a team-signed build (Signing.xcconfig); an
/// ad-hoc build reports the keystore unsupported rather than storing the key
/// anywhere weaker.
final class KeychainKeystore: DeviceKeystore {
    private let service: String
    private let scope: KeychainScope
    private let account = "device-wrapping-key"
    private let lock = NSLock()
    private var promptReason: String?
    private var activeContext: LAContext?

    init(service: String, scope: KeychainScope) {
        self.scope = scope
        self.service = service
    }

    /// The Touch ID sheet's reason, in the current language.
    func setPromptReason(_ reason: String) {
        lock.withLock { promptReason = reason }
    }

    func cancelUnlock() {
        let context = lock.withLock { activeContext }
        context?.invalidate()
    }

    /// Never prompts: it reads this process's own entitlements, and
    /// LocalAuthentication only evaluates.
    func status() -> PlatformKeystoreStatus {
        guard Keychain.dataProtectionAvailable(scope: scope) else {
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
        try storeKey(account: account, key: dwk, replacing: true)
    }
    func storeBackupKey(keyId: Data, key: Data) throws {
        try storeKey(account: "backup-recipient-" + keyId.base64EncodedString(), key: key, replacing: false)
    }
    private func storeKey(account: String, key: Data, replacing: Bool) throws {
        let current = status()
        guard current.supported else { throw PlatformStoreError.Unsupported }
        guard current.biometricsAvailable else {
            throw PlatformStoreError.Unavailable(message: current.message ?? "Biometric authentication is not available")
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &error
        ) else {
            let message = error.map { CFErrorCopyDescription($0.takeRetainedValue()) as String }
            throw PlatformStoreError.Unavailable(message: message ?? "access control unavailable")
        }
        // An access control cannot be updated in place: replace the item.
        if replacing { try Keychain.delete(service: service, account: account, dataProtection: true, scope: scope) }
        try Keychain.add(
            service: service, account: account, data: key,
            protection: [kSecAttrAccessControl: access], dataProtection: true, scope: scope
        )
    }

    /// Presents Touch ID; the core calls this off the main thread.
    func loadDwk() throws -> Data? { try loadKey(account: account) }
    func loadBackupKey(keyId: Data) throws -> Data? { try loadKey(account: "backup-recipient-" + keyId.base64EncodedString()) }
    private func loadKey(account: String) throws -> Data? {
        let context = LAContext()
        context.localizedReason = try lock.withLock {
            guard let promptReason, !promptReason.isEmpty else {
                throw PlatformStoreError.Unavailable(message: "Biometric prompt is not configured")
            }
            guard activeContext == nil else {
                throw PlatformStoreError.Unavailable(message: "Biometric unlock is already in progress")
            }
            activeContext = context
            return promptReason
        }
        defer {
            lock.withLock { activeContext = nil }
            context.invalidate()
        }
        return try Keychain.get(
            service: service, account: account, dataProtection: true, scope: scope,
            extra: [kSecUseAuthenticationContext: context]
        )
    }

    func deleteDwk() throws {
        try Keychain.delete(service: service, account: account, dataProtection: true, scope: scope)
    }
    func deleteBackupKey(keyId: Data) throws {
        try Keychain.delete(service: service, account: "backup-recipient-" + keyId.base64EncodedString(), dataProtection: true, scope: scope)
    }

}

/// Session tokens under the service and account names the core chooses. The
/// core calls this from background threads, so it must never need user
/// presence.
final class KeychainSecretStore: PlatformSecretStore {
    private let scope: KeychainScope
    init(scope: KeychainScope) { self.scope = scope }
    func put(service: String, account: String, secret: String) throws {
        try Keychain.put(
            service: service, account: account, data: Data(secret.utf8),
            accessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, scope: scope
        )
    }

    func get(service: String, account: String) throws -> String? {
        guard let data = try Keychain.get(service: service, account: account, scope: scope) else { return nil }
        guard let value = String(data: data, encoding: .utf8) else {
            throw PlatformStoreError.Unavailable(message: "Keychain credential is not valid UTF-8")
        }
        return value
    }

    func delete(service: String, account: String) throws {
        try Keychain.delete(service: service, account: account, scope: scope)
    }
}
