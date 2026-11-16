import Foundation
import ZannCoreKit

/// Keys never enter Swift: selected files and explicit targets go to Rust.
@MainActor final class PasskeyExchangeModel: ObservableObject {
    @Published private(set) var busy = false
    @Published private(set) var failure: Error?
    @Published private(set) var targets: [PasskeyTargetSummaryFfi] = []
    @Published private(set) var preview: PasskeyImportPreviewFfi?
    @Published private(set) var report: PasskeyImportReportFfi?
    @Published private(set) var artifact: TemporaryExport?
    private let core: CoreFacade
    private let root: URL
    private var source: ScopedBackupURL?
    private var format: PasskeyExchangeFormatFfi?
    private var operation: SessionOperationFfi?
    private var generation = 0
    init(core: CoreFacade, root: URL) { self.core = core; self.root = root }
    func load() async {
        guard !busy else { return }
        busy = true; failure = nil
        let epoch = generation, core = core
        defer { if epoch == generation { busy = false } }
        let result = await BlockingCore.run { Result { try core.passkeyTargets() } }
        guard epoch == generation else { return }
        switch result { case .success(let rows): targets = rows; case .failure(let error): failure = error }
    }
    func choose(_ url: URL, format: PasskeyExchangeFormatFfi) async {
        guard !busy else { return }
        source = nil; preview = nil; report = nil; failure = nil
        let lease = ScopedBackupURL(url)
        source = lease; self.format = format
        let epoch = generation, core = core
        busy = true; defer { if epoch == generation { busy = false } }
        let result = await BlockingCore.run { Result { try core.passkeyPreflightFile(path: lease.url.path, format: format) } }
        guard epoch == generation else { return }
        switch result { case .success(let value): preview = value; case .failure(let error): source = nil; failure = error }
    }
    func restore(target: PasskeyTargetFfi) async {
        guard let source, let format, preview != nil, !busy else { return }
        let epoch = generation, core = core
        busy = true; failure = nil; defer { if epoch == generation { busy = false } }
        do {
            let pending = try SessionOperationFfi(timeoutMs: 120_000); operation = pending
            defer { if epoch == generation { operation = nil } }
            let result = await BlockingCore.run { Result { try core.passkeyImportFile(path: source.url.path, format: format, target: target, operation: pending) } }
            guard epoch == generation else { return }
            switch result { case .success(let value): report = value; preview = nil; self.source = nil; case .failure(let error): failure = error }
        } catch { failure = error }
    }
    func export(target: PasskeyTargetFfi, authorization: ExportAuthorizationFfi, operation: SessionOperationFfi) async -> Error? {
        guard !busy else { return nil }
        busy = true; failure = nil; self.operation = operation
        let epoch = generation, core = core, root = root
        defer { if epoch == generation { busy = false; self.operation = nil } }
        let result = await BlockingCore.run { Result { try TemporaryExport.prepareCxf(core: core, root: root, target: target, authorization: authorization) } }
        switch result {
        case .success(let file): if epoch == generation { artifact = file } else { remove(file) }
        case .failure(let error): if epoch == generation { failure = error }
        }
        return failure
    }
    func finishExport(_ error: Error?) { if let error { failure = error }; if let artifact { self.artifact = nil; remove(artifact) } }
    func cancel() {
        generation += 1; busy = false; format = nil; operation?.cancel(); operation = nil; source = nil; preview = nil; report = nil; targets = []
        finishExport(nil)
    }
    private func remove(_ file: TemporaryExport) {
        if case .failure(let error) = Result(catching: file.remove) {
            if let original = failure { failure = TemporaryExport.CleanupFailure(original: original, cleanup: error) }
            else { failure = error }
        }
    }
}
