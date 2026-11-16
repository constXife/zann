import SwiftUI

#if os(iOS)
import UIKit

/// Save a copy through Files; the picker owns access to the chosen destination.
struct BackupExportPicker: UIViewControllerRepresentable {
    let file: URL
    let finished: (Error?) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(finished: finished) }
    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(forExporting: [file], asCopy: true)
        picker.delegate = context.coordinator
        return picker
    }
    func updateUIViewController(_ controller: UIDocumentPickerViewController, context: Context) {}

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let finished: (Error?) -> Void
        init(finished: @escaping (Error?) -> Void) { self.finished = finished }
        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) { finished(nil) }
        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) { finished(nil) }
    }
}
#else
import AppKit
import UniformTypeIdentifiers

struct BackupExportPicker: View {
    let file: URL
    let finished: (Error?) -> Void
    var body: some View {
        ProgressView().padding().task {
            let panel = NSSavePanel()
            panel.allowedContentTypes = [file.pathExtension == "json" ? .json : .data]
            panel.nameFieldStringValue = file.lastPathComponent
            let response = await withTaskCancellationHandler {
                await panel.begin()
            } onCancel: {
                Task { @MainActor in panel.cancel(nil) }
            }
            guard !Task.isCancelled, response == .OK, let destination = panel.url else { finished(nil); return }
            let source = file
            let result = await BlockingCore.run { Result {
                try ExportDestination.copy(source: source, to: destination)
            } }
            if case .failure(let error) = result { finished(error) } else { finished(nil) }
        }
    }
}

enum ExportDestination {
    static func copy(source: URL, to destination: URL) throws {
        let manager = FileManager.default
        let staging = destination.deletingLastPathComponent().appendingPathComponent(".\(UUID().uuidString)").appendingPathExtension(source.pathExtension)
        do {
            try manager.copyItem(at: source, to: staging)
            if manager.fileExists(atPath: destination.path) {
                // Preserve the new file's 0600 mode when replacing a public file.
                _ = try manager.replaceItemAt(destination, withItemAt: staging, options: .usingNewMetadataOnly)
            } else { try manager.moveItem(at: staging, to: destination) }
        } catch {
            let original = error
            do { try TemporaryExport.purge(staging) }
            catch { throw TemporaryExport.CleanupFailure(original: original, cleanup: error) }
            throw original
        }
    }
}
#endif
