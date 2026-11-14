import XCTest
import ZannCoreKit
@testable import Zann

@MainActor final class ItemDetailLoaderTests: XCTestCase {
    private nonisolated static func card(_ id: String) -> ItemDetailViewFfi {
        ItemDetailViewFfi(id: id, title: id, path: id, typeId: "login", fields: [])
    }

    func testReplacementCancelsNativeOperationAndDropsLateSuccess() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let core = try createCore(dbPath: dir.appendingPathComponent("local.sqlite").path,
                                  keystore: MemoryKeystore(), secretStore: MemorySecretStore())
        let started = expectation(description: "old read started")
        let cancelled = expectation(description: "native operation cancelled")
        let newReceived = expectation(description: "new card received")
        let gate = DispatchSemaphore(value: 0)
        defer { gate.signal() }
        let loader = ItemDetailLoader(read: { id, operation in
            if id == "old" {
                started.fulfill()
                gate.wait()
                do {
                    _ = try core.itemDetail(id: "invalid", operation: operation)
                    XCTFail("a superseded operation must be cancelled before dispatch")
                } catch CoreError.Cancelled {
                    cancelled.fulfill()
                }
            }
            return Self.card(id)
        })
        var received: [String] = []
        loader.load("old") { result in received.append((try? result.get().id) ?? "error") }
        await fulfillment(of: [started], timeout: 2)
        loader.load("new") { result in
            received.append((try? result.get().id) ?? "error")
            newReceived.fulfill()
        }
        await fulfillment(of: [newReceived], timeout: 2)
        gate.signal()
        await fulfillment(of: [cancelled], timeout: 2)
        // The old read deliberately returns success after noticing cancellation.
        // It must still never publish over the replacement.
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(received, ["new"])
    }

    func testCancelAndDeinitStopNativeReadWithoutPublishing() async throws {
        for release in [false, true] {
            let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            defer { try? FileManager.default.removeItem(at: dir) }
            let core = try createCore(dbPath: dir.appendingPathComponent("local.sqlite").path,
                                      keystore: MemoryKeystore(), secretStore: MemorySecretStore())
            let started = expectation(description: "read started")
            let cancelled = expectation(description: "native operation cancelled")
            let received = expectation(description: "no card after cancellation")
            received.isInverted = true
            let gate = DispatchSemaphore(value: 0)
            defer { gate.signal() }
            var loader: ItemDetailLoader? = ItemDetailLoader(read: { id, operation in
                started.fulfill()
                gate.wait()
                do {
                    _ = try core.itemDetail(id: "invalid", operation: operation)
                    XCTFail("operation must be cancelled")
                } catch CoreError.Cancelled {
                    cancelled.fulfill()
                }
                return Self.card(id)
            })
            loader?.load("old") { _ in received.fulfill() }
            await fulfillment(of: [started], timeout: 2)
            if release {
                loader = nil
            } else {
                loader?.cancel()
            }
            gate.signal()
            await fulfillment(of: [cancelled], timeout: 2)
            await fulfillment(of: [received], timeout: 0.1)
        }
    }
}
