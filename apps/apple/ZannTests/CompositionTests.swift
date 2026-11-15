import XCTest
import ZannCoreKit
#if os(iOS)
@testable import ZannMobile
#else
@testable import Zann
#endif

final class CompositionTests: XCTestCase {
    private func identity(
        vaultGroup: String = "TEAM.example.vault", tokenGroup: String = "TEAM.example.app"
    ) throws -> MobileIdentity {
        try MobileIdentity(
            appGroup: "group.example.zann", vaultService: "example.zann.unlock",
            vaultAccessGroup: vaultGroup, tokenAccessGroup: tokenGroup
        )
    }

    func testMacRootAndPreferenceLocationRemainUnchanged() throws {
        let support = URL(fileURLWithPath: "/tmp/Application Support", isDirectory: true)
        let storage = try AppleStorage.macOS(
            applicationSupport: support, bundleIdentifier: "com.rlyeh.zann.apple"
        )
        XCTAssertEqual(storage.database.path, "/tmp/Application Support/com.rlyeh.zann.apple/local.sqlite")
        XCTAssertEqual(storage.preferences.url.deletingLastPathComponent(), storage.directory)
        XCTAssertEqual(storage.preferences.url.lastPathComponent, "preferences.json")
    }

    func testMissingOrPathLikeBundleIdentifierCannotSelectARoot() {
        for identifier in [nil, "", ".", "..", "../other", "other/root"] as [String?] {
            XCTAssertThrowsError(try AppleStorage.macOS(
                applicationSupport: URL(fileURLWithPath: "/tmp"), bundleIdentifier: identifier
            )) { XCTAssertEqual($0 as? AppleCompositionError, .missingBundleIdentifier) }
        }
    }

    func testStorageRejectsNonlocalURLsAndParentTraversal() throws {
        for text in ["https://example.test/root", "file://other-host/root", "file:///tmp/../other",
                     "file:///tmp/root?query", "file:///tmp/root#fragment"] {
            let directory = try XCTUnwrap(URL(string: text))
            XCTAssertThrowsError(try AppleStorage(directory: directory)) {
                XCTAssertEqual($0 as? AppleCompositionError, .invalidStorageDirectory)
            }
        }
    }

    func testMobileRootComesOnlyFromTheRequestedAppGroup() throws {
        let container = URL(fileURLWithPath: "/tmp/App Group", isDirectory: true)
        let config = try identity()
        var requested: [String] = []
        let mobile = try MobileComposition(identity: config) { group in
            requested.append(group)
            return container
        }
        XCTAssertEqual(requested, [config.appGroup])
        XCTAssertEqual(mobile.storage.database.path, "/tmp/App Group/Library/Application Support/Zann/local.sqlite")
        XCTAssertEqual(mobile.storage.preferences.url.deletingLastPathComponent(), mobile.storage.directory)
        XCTAssertEqual(try MobileComposition(identity: config) { _ in container }.storage, mobile.storage)
    }

    func testMissingEntitledContainerFailsWithoutChoosingAnotherRoot() throws {
        let config = try identity()
        var requests = 0
        XCTAssertThrowsError(try MobileComposition(identity: config) { _ in
            requests += 1
            return nil
        }) { XCTAssertEqual($0 as? AppleCompositionError, .appGroupUnavailable(config.appGroup)) }
        XCTAssertEqual(requests, 1)
    }

    func testMobileIdentityRejectsSharedTokenAndVaultGroupsAndUnresolvedSettings() throws {
        XCTAssertThrowsError(try identity(vaultGroup: "TEAM.example.shared", tokenGroup: "TEAM.example.shared"))
        XCTAssertThrowsError(try identity(tokenGroup: "group.example.zann"))
        for value in ["", " ", "$(AppIdentifierPrefix)example.app"] {
            XCTAssertThrowsError(try identity(tokenGroup: value)) {
                XCTAssertEqual($0 as? AppleCompositionError, .invalidMobileIdentity)
            }
        }
        XCTAssertThrowsError(try MobileIdentity(
            appGroup: "", vaultService: "example.unlock",
            vaultAccessGroup: "TEAM.vault", tokenAccessGroup: "TEAM.app"
        ))
    }

    func testMobileFactoriesReceiveDistinctExplicitNamespacesAndPreserveTheirError() throws {
        let mobile = try MobileComposition(identity: identity()) { _ in URL(fileURLWithPath: "/tmp/group") }
        let failure = NSError(domain: "CompositionTest", code: 42)
        var tokenFactoryCalled = false
        XCTAssertThrowsError(try mobile.compose(keystore: { service, group in
            XCTAssertEqual(service, mobile.identity.vaultService)
            XCTAssertEqual(group, mobile.identity.vaultAccessGroup)
            throw failure
        }, secretStore: { _ in
            tokenFactoryCalled = true
            return MemorySecretStore()
        })) { XCTAssertTrue(($0 as NSError) === failure) }
        XCTAssertFalse(tokenFactoryCalled)
    }

    func testMobileCoreUsesTheGroupRootAndNeverStartsDesktopIPC() throws {
        let container = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: container) }
        let mobile = try MobileComposition(identity: identity()) { _ in container }
        let composition = mobile.compose(keystore: { service, group in
            XCTAssertEqual(service, mobile.identity.vaultService)
            XCTAssertEqual(group, mobile.identity.vaultAccessGroup)
            return MemoryKeystore()
        }, secretStore: { group in
            XCTAssertEqual(group, mobile.identity.tokenAccessGroup)
            return MemorySecretStore()
        })
        XCTAssertFalse(FileManager.default.fileExists(atPath: container.path), "composition must not open storage")
        let opened = try composition.openCore()
        XCTAssertFalse(try opened.core.appStatus().initialized)
        XCTAssertTrue(FileManager.default.fileExists(atPath: mobile.storage.database.path))
        XCTAssertThrowsError(try opened.core.browserPairings()) { error in
            #if os(iOS)
            guard case CoreError.Unimplemented = error else {
                return XCTFail("desktop IPC must be unavailable on iOS")
            }
            #else
            guard case CoreError.Browser(.notRunning, _) = error else {
                return XCTFail("expected desktop IPC to remain stopped")
            }
            #endif
        }
    }
}
