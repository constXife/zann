import XCTest
import ZannCoreKit
@testable import ZannMobile

final class MobileSmokeTests: XCTestCase {
    func testHostContainsAnExpandedMobileIdentityAndBothDeviceFamilies() throws {
        let identity = try MobileTargetConfiguration.identity(bundle: .main)
        XCTAssertNotEqual(identity.vaultAccessGroup, identity.tokenAccessGroup)
        XCTAssertNotEqual(identity.appGroup, identity.tokenAccessGroup)
        XCTAssertEqual(Bundle.main.object(forInfoDictionaryKey: "UIDeviceFamily") as? [Int], [1, 2])
        XCTAssertThrowsError(try MobileTargetConfiguration.identity(bundle: Bundle(for: Self.self)))
    }

    func testNativeRedirectIsRegisteredUnderTheSameExpandedScheme() throws {
        let redirect = try MobileTargetConfiguration.oidcRedirectURI(bundle: .main)
        let scheme = try XCTUnwrap(URL(string: redirect)?.scheme)
        let types = try XCTUnwrap(Bundle.main.object(forInfoDictionaryKey: "CFBundleURLTypes") as? [[String: Any]])
        let schemes = types.compactMap { $0["CFBundleURLSchemes"] as? [String] }.flatMap { $0 }
        XCTAssertEqual(schemes, [scheme])
        XCTAssertEqual(redirect, "\(scheme):/oidc/callback")
        XCTAssertFalse(redirect.contains("$("))
        XCTAssertThrowsError(try MobileTargetConfiguration.oidcRedirectURI(bundle: Bundle(for: Self.self)))
    }

    func testSyntheticReplicaSurvivesLockAndReopenInsideTheSelectedMobileRoot() throws {
        let identity = try MobileTargetConfiguration.identity(bundle: .main)
        let container = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: container) }
        let mobile = try MobileComposition(identity: identity) { group in
            XCTAssertEqual(group, identity.appGroup)
            return container
        }
        let keystore = MemoryKeystore()
        let secrets = MemorySecretStore()
        let composition = mobile.compose(keystore: { _, _ in keystore }, secretStore: { _ in secrets })
        let password = "mobile fixture password"
        let storageID: String
        do {
            let core = try composition.openCore().core
            XCTAssertFalse(try core.appStatus().initialized)
            _ = try core.seedOfflineFixture(password: password)
            storageID = try XCTUnwrap(core.currentStorageId())
            XCTAssertFalse(try core.listVaults().isEmpty)
            _ = try core.lock()
        }
        let reopened = try composition.openCore().core
        XCTAssertTrue(try reopened.appStatus().initialized)
        _ = try reopened.unlock(password: password)
        XCTAssertEqual(reopened.currentStorageId(), storageID)
        XCTAssertFalse(try reopened.listVaults().isEmpty)
    }
}
