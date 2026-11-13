import SQLite3
import XCTest
import ZannCoreKit
@testable import Zann

/// Test-only cached server projection; copies encrypted keys inside a temporary DB.
func seedStorageContext(database: URL) throws -> String {
    var db: OpaquePointer?
    guard sqlite3_open(database.path, &db) == SQLITE_OK else {
        throw NSError(domain: "StorageFixture", code: 1)
    }
    defer { sqlite3_close(db) }
    let sql = """
        INSERT INTO storages (id, kind, name, server_url)
        VALUES (X'123456781234123412341234567890ab', 2, 'Remote', 'https://work.example.test');
        INSERT INTO local_vaults (id, storage_id, slug, name, kind, is_default, vault_key_enc, key_wrap_type)
        SELECT id, X'123456781234123412341234567890ab', slug, name, kind, is_default, vault_key_enc, key_wrap_type
        FROM local_vaults WHERE storage_id = X'00000000000000000000000000000000';
        """
    guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
        throw NSError(domain: "StorageFixture", code: Int(sqlite3_errcode(db)))
    }
    return "12345678-1234-1234-1234-1234567890ab"
}

@MainActor
final class StorageContextTests: XCTestCase {
    func testSwitchClearsSearchDetailAndLoadsTargetCounts() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let database = dir.appendingPathComponent("local.sqlite")
        let core = try createCore(dbPath: database.path, keystore: MemoryKeystore(), secretStore: MemorySecretStore())
        _ = try core.initializeMasterPassword(password: "storage test password")
        let local = core.currentStorageId()
        let remote = try seedStorageContext(database: database)
        let model = VaultModel(core: core, contents: try VaultModel.load(core), strings: Strings(language: "en"))
        XCTAssertEqual(model.storages.first(where: { $0.id == remote })?.displayName, "work.example.test")
        model.startCreating(typeID: "note")
        try XCTUnwrap(model.editor).name = "Local note"
        await model.saveEditor()
        model.query = "Local"
        model.categoryID = "note"
        await model.selectStorage(remote)
        XCTAssertEqual(model.storageID, remote)
        XCTAssertEqual(core.currentStorageId(), remote)
        XCTAssertEqual(model.query, "")
        XCTAssertEqual(model.categoryID, "all")
        XCTAssertNil(model.detail)
        XCTAssertNil(model.selectedItemID)
        XCTAssertTrue(model.visibleItems.isEmpty)
        XCTAssertEqual(model.totalCount, 0)
        XCTAssertEqual(model.syncState?.serverUrl, "https://work.example.test")
        XCTAssertEqual(model.syncState?.link, .disconnected)
        XCTAssertEqual(model.disconnected?.serverURL, "https://work.example.test")
        try await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertTrue(model.visibleItems.isEmpty, "a superseded search must not restore the old list")
        model.startCreating(typeID: "note")
        try XCTUnwrap(model.editor).name = "Work note"
        await model.saveEditor()
        await model.selectStorage(local)
        XCTAssertEqual(model.visibleItems.map(\.title), ["Local note"])
        await model.selectStorage(remote)
        XCTAssertEqual(model.visibleItems.map(\.title), ["Work note"])
        model.startCreating(typeID: "login")
        await model.selectStorage(local)
        XCTAssertEqual(model.storageID, remote, "an open draft holds its storage")
        model.cancelEditing()
        _ = try core.lock()
        await model.selectStorage(local)
        XCTAssertEqual(model.storageID, remote, "a refused switch keeps the current context")
        XCTAssertNotNil(model.error)
    }
}
