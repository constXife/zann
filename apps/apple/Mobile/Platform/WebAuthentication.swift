import AuthenticationServices
import UIKit
import ZannCoreKit

/// Retains exactly one system sheet/continuation and discards late callbacks.
@MainActor
final class WebAuthentication: NSObject, ASWebAuthenticationPresentationContextProviding {
    weak var window: UIWindow?
    private var anchor: UIWindow?
    private var session: ASWebAuthenticationSession?
    private var continuation: CheckedContinuation<URL, Error>?
    private var timeout: Task<Void, Never>?
    private var generation = 0

    func authorize(url: URL, scheme: String, timeoutMs: UInt64) async throws -> URL {
        guard timeoutMs > 0 else {
            throw CoreError.Oidc(kind: .deadlineExceeded, message: "Browser sign-in timed out")
        }
        guard continuation == nil, let window else {
            throw CoreError.InvalidArgument("No active window for browser sign-in")
        }
        generation += 1
        let started = generation
        anchor = window
        return try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { continuation in
                self.continuation = continuation
                let session = ASWebAuthenticationSession(url: url, callbackURLScheme: scheme) { [weak self] url, error in
                    Task { @MainActor in
                        guard let self, self.generation == started else { return }
                        if let error = error as NSError? {
                            if error.domain == ASWebAuthenticationSessionErrorDomain,
                               error.code == ASWebAuthenticationSessionError.canceledLogin.rawValue {
                                self.complete(.failure(CoreError.Oidc(kind: .cancelled, message: "Browser sign-in cancelled")))
                            } else {
                                self.complete(.failure(NSError(
                                    domain: "ZannWebAuthentication", code: error.code,
                                    userInfo: [NSLocalizedDescriptionKey: "Browser sign-in failed", NSUnderlyingErrorKey: error]
                                )))
                            }
                        } else if let url {
                            self.complete(.success(url))
                        } else {
                            self.complete(.failure(CoreError.Oidc(kind: .protocol, message: "Missing browser callback")))
                        }
                    }
                }
                self.session = session
                session.presentationContextProvider = self
                timeout = Task { [weak self] in
                    try? await Task.sleep(nanoseconds: min(timeoutMs, UInt64.max / 1_000_000) * 1_000_000)
                    guard !Task.isCancelled, let self, self.generation == started else { return }
                    self.complete(.failure(CoreError.Oidc(kind: .deadlineExceeded, message: "Browser sign-in timed out")))
                }
                if !session.start() {
                    complete(.failure(CoreError.Oidc(kind: .configuration, message: "Browser sign-in could not start")))
                }
            }
        }, onCancel: { [weak self] in
            Task { @MainActor in
                guard self?.generation == started else { return }
                self?.cancel()
            }
        })
    }

    func cancel() {
        complete(.failure(CoreError.Oidc(kind: .cancelled, message: "Browser sign-in cancelled")))
    }

    private func complete(_ result: Result<URL, Error>) {
        generation += 1
        let pending = continuation
        continuation = nil
        timeout?.cancel()
        timeout = nil
        let session = session
        self.session = nil
        anchor = nil
        session?.cancel()
        pending?.resume(with: result)
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        guard let anchor else { preconditionFailure("Browser presentation without an active request") }
        return anchor
    }
}
