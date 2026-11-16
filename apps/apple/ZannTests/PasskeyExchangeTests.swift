import XCTest
import ZannCoreKit
#if os(iOS)
@testable import ZannMobile
#else
@testable import Zann
#endif

@MainActor final class PasskeyExchangeTests: XCTestCase {
    private var root: URL!
    private var core: CoreFacade!
    private var model: PasskeyExchangeModel!
    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        core = try createCore(dbPath: root.appendingPathComponent("local.sqlite").path, keystore: MemoryKeystore(), secretStore: MemorySecretStore())
        _ = try core.seedOfflineFixture(password: "synthetic passkey fixture password")
        model = PasskeyExchangeModel(core: core, root: root.appendingPathComponent("exports"))
    }
    override func tearDownWithError() throws {
        model?.cancel(); model = nil; core = nil
        try FileManager.default.removeItem(at: root)
    }
    func testFileImportAndFreshCxfExportUseNativePolicyAndClearPrivateArtifact() async throws {
        await model.load()
        let target = try XCTUnwrap(model.targets.first?.target)
        var repository = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 { repository.deleteLastPathComponent() }
        await model.choose(repository.appendingPathComponent("tests/fixtures/passkey-exchange/cxf.json"), format: .cxf)
        XCTAssertNil(model.failure)
        XCTAssertEqual(model.preview?.credentials, 1)
        await model.restore(target: target)
        XCTAssertEqual(model.report?.imported, 1)
        XCTAssertTrue(try core.verify().problems.isEmpty)
        let operation = try SessionOperationFfi(timeoutMs: 120_000)
        let authorization = try core.authorizeExport(proof: .init(password: "synthetic passkey fixture password", factor: .devicePassword, pin: nil), operation: operation)
        let failure = await model.export(target: target, authorization: authorization, operation: operation)
        XCTAssertNil(failure)
        let artifact = try XCTUnwrap(model.artifact)
        XCTAssertTrue(FileManager.default.fileExists(atPath: artifact.file.path))
        model.finishExport(nil)
        XCTAssertFalse(FileManager.default.fileExists(atPath: artifact.directory.path))
        XCTAssertThrowsError(try core.passkeyExportCxf(path: root.appendingPathComponent("replay.json").path, target: target, authorization: authorization))
        model.cancel()
        XCTAssertNil(model.preview)
        XCTAssertTrue(model.targets.isEmpty)
    }
    func testCanceledLoadCanReopenWhileOldReadIsStillPending() async throws {
        let delayed = DelayedPasskeyCore(unsafeFromRawPointer: core.uniffiClonePointer())
        let started = expectation(description: "first target read delayed")
        delayed.started = { started.fulfill() }
        let model = PasskeyExchangeModel(core: delayed, root: root.appendingPathComponent("delayed-exports"))
        let old = Task { await model.load() }
        defer { delayed.gate.signal() }
        await fulfillment(of: [started], timeout: 2)
        model.cancel()
        await model.load()
        XCTAssertFalse(model.targets.isEmpty)
        delayed.gate.signal()
        await old.value
        XCTAssertFalse(model.busy)
        XCTAssertFalse(model.targets.isEmpty)
    }

}

private final class DelayedPasskeyCore: CoreFacade {
    let gate = DispatchSemaphore(value: 0)
    var started: (() -> Void)?
    private let mutex = NSLock()
    private var delayed = false
    override func passkeyTargets() throws -> [PasskeyTargetSummaryFfi] {
        mutex.lock(); let wait = !delayed; delayed = true; mutex.unlock()
        if wait {
            started?()
            guard gate.wait(timeout: .now() + 10) == .success else { throw CoreError.Service("fixture target gate timed out") }
        }
        return try super.passkeyTargets()
    }
}
