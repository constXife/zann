import XCTest
import ZannCoreKit
#if os(iOS)
@testable import ZannMobile
#else
@testable import Zann
#endif

@MainActor final class EncryptedBackupTests: XCTestCase {
    private var root: URL!
    private var core: CoreFacade!
    private var keystore: MemoryKeystore!
    private var model: EncryptedBackupModel!
    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        keystore = MemoryKeystore()
        core = try createCore(dbPath: root.appendingPathComponent("local.sqlite").path,
                              keystore: keystore, secretStore: MemorySecretStore())
        _ = try core.seedOfflineFixture(password: "synthetic encrypted backup fixture")
        _ = try core.itemCreate(create: .init(title: "Synthetic note", path: "Synthetic note", typeId: "note",
            payloadJson: #"{"v":1,"typeId":"note","fields":{"notes":{"kind":"text","value":"portable sentinel secret"}}}"#))
        model = EncryptedBackupModel(core: core, root: root.appendingPathComponent("exports"))
    }
    override func tearDownWithError() throws {
        model?.cancel(); model = nil; core = nil; keystore = nil
        try FileManager.default.removeItem(at: root)
    }
    private func phrase() -> BackupRecipientFfi {
        .init(kind: .passphrase, passphrase: "synthetic portable phrase", pin: nil, builtInUv: false)
    }
    func testEncryptedExportAndIndependentReadOnlyVerificationNeverArmRememberedUnlock() async throws {
        await model.begin()
        await model.add(phrase())
        await model.add(.init(kind: .biometric, passphrase: nil, pin: nil, builtInUv: false))
        XCTAssertFalse(keystore.holdsKey)
        await model.export()
        let artifact = try XCTUnwrap(model.artifact)
        XCTAssertNil(model.failure)
        let bytes = try Data(contentsOf: artifact.file)
        XCTAssertNil(bytes.range(of: Data("portable sentinel secret".utf8)))
        let saved = root.appendingPathComponent("saved.zann")
        try FileManager.default.copyItem(at: artifact.file, to: saved)
        model.finishExport(nil)
        XCTAssertFalse(FileManager.default.fileExists(atPath: artifact.directory.path))
        await model.chooseSource(saved)
        XCTAssertEqual(model.recipients.count, 2)
        await model.open(slot: 0, recipient: phrase())
        XCTAssertEqual(model.inspection?.itemsCount, 1)
        XCTAssertNil(model.failure)
        XCTAssertFalse(keystore.holdsKey)
    }
    func testBiometricOnlyIsRefusedAndCancellationCleansArtifactsAndReports() async throws {
        await model.begin()
        await model.add(.init(kind: .biometric, passphrase: nil, pin: nil, builtInUv: false))
        await model.export()
        XCTAssertNil(model.artifact)
        XCTAssertNotNil(model.failure)
        XCTAssertFalse(model.canExport)
        await model.begin()
        await model.add(phrase())
        await model.export()
        let artifact = try XCTUnwrap(model.artifact)
        model.cancel()
        XCTAssertFalse(FileManager.default.fileExists(atPath: artifact.directory.path))
        XCTAssertNil(model.inspection)
        XCTAssertTrue(model.recipients.isEmpty)
    }
}
