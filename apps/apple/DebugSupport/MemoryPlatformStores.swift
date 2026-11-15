#if DEBUG
import Foundation
import ZannCoreKit
#if !ZANN_UI_FIXTURE_HOST
#if os(iOS)
@testable import ZannMobile
#else
@testable import Zann
#endif
#endif

/// A keystore that always "passes" Touch ID, unless `cancelLoads` makes it
/// behave like a dismissed prompt.
final class MemoryKeystore: DeviceKeystore {
    private var dwk: Data?
    private(set) var promptReason = ""
    var cancelLoads = false
    var biometricsAvailable = true
    private(set) var loadCalls = 0

    var holdsKey: Bool { dwk != nil }
    var onLoad: (() -> Void)?
    private(set) var cancelCalls = 0
    func cancelUnlock() { cancelCalls += 1 }

    func setPromptReason(_ reason: String) { promptReason = reason }

    func status() -> PlatformKeystoreStatus {
        PlatformKeystoreStatus(
            supported: true, biometricsAvailable: biometricsAvailable, reason: nil, message: nil
        )
    }

    func storeDwk(dwk: Data) throws { self.dwk = dwk }

    func loadDwk() throws -> Data? {
        loadCalls += 1
        onLoad?()
        if cancelLoads { throw PlatformStoreError.Cancelled }
        return dwk
    }

    func deleteDwk() throws { dwk = nil }
}

final class MemorySecretStore: PlatformSecretStore {
    private var values: [String: String] = [:]

    func put(service: String, account: String, secret: String) throws {
        values["\(service)/\(account)"] = secret
    }

    func get(service: String, account: String) throws -> String? {
        values["\(service)/\(account)"]
    }

    func delete(service: String, account: String) throws {
        values["\(service)/\(account)"] = nil
    }
}

#endif
