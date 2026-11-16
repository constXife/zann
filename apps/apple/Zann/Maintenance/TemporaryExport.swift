import Foundation
import ZannCoreKit

/// One native file-picker lease. The core streams directly into a fresh private
/// directory; Swift never loads the plaintext backup into memory.
struct TemporaryExport: Identifiable {
    let id = UUID()
    let directory: URL
    let filename: String
    var file: URL { directory.appendingPathComponent(filename) }

    static func prepare(core: CoreFacade, root: URL, authorization: ExportAuthorizationFfi) throws -> TemporaryExport {
        try prepare(root: root, filename: "zann-backup.json") { file in
            _ = try core.backupExportFile(path: file.path, authorization: authorization)
        }
    }
    static func prepareEncrypted(core: CoreFacade, root: URL, handle: BackupHandleFfi) throws -> TemporaryExport {
        try prepare(root: root, filename: "zann-backup.zann") { file in
            _ = try core.backupExportEncrypted(path: file.path, handle: handle)
        }
    }
    private static func prepare(root: URL, filename: String, write: (URL) throws -> Void) throws -> TemporaryExport {
        let manager = FileManager.default
        var attributes: [FileAttributeKey: Any] = [.posixPermissions: 0o700]
        #if os(iOS)
        attributes[.protectionKey] = FileProtectionType.complete
        #endif
        try manager.createDirectory(at: root, withIntermediateDirectories: true, attributes: attributes)
        let export = TemporaryExport(directory: root.appendingPathComponent(UUID().uuidString), filename: filename)
        try manager.createDirectory(at: export.directory, withIntermediateDirectories: false, attributes: attributes)
        do {
            try write(export.file)
            var excluded = export.directory
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try excluded.setResourceValues(values)
            return export
        } catch {
            // Resource cleanup is required even when the core leaves a partial
            // export. Preserve both failures if removal also fails.
            let original = error
            do { try export.remove() }
            catch { throw CleanupFailure(original: original, cleanup: error) }
            throw original
        }
    }

    func remove() throws { try Self.purge(directory) }

    /// Also used at launch to remove a plaintext artifact left by process death.
    static func purge(_ root: URL) throws {
        do { try FileManager.default.removeItem(at: root) }
        catch let error as CocoaError where error.code == .fileNoSuchFile { return }
    }

    struct CleanupFailure: LocalizedError {
        let original: Error
        let cleanup: Error
        var errorDescription: String? {
            "\(describe(original))\nCleanup: \(cleanup.localizedDescription)"
        }
    }
}
