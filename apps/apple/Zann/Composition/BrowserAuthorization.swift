import Foundation
import ZannCoreKit

/// Platform effects for one shared Connect flow. Rust owns the callback
/// contract, PKCE/state validation, provider exchange and session commit.
@MainActor
enum BrowserAuthorization {
    case loopback(open: (URL) -> Void)
    case system(
        redirectURI: Result<String, Error>,
        authorize: (URL, String, UInt64) async throws -> URL,
        cancel: () -> Void
    )

    func callback() throws -> OidcCallbackFfi {
        switch self {
        case .loopback: return .loopback
        case .system(let uri, _, _): return .application(redirectUri: try uri.get())
        }
    }

    var canReopen: Bool {
        if case .loopback = self { return true }
        return false
    }

    func finish(_ login: OidcLoginFfi) async throws -> SessionAccessFfi {
        guard let url = URL(string: login.authorizationUrl()) else {
            throw CoreError.InvalidArgument("Invalid authorization URL")
        }
        switch self {
        case .loopback:
            return try await BlockingCore.run { Result { try login.finish() } }.get()
        case .system(_, let authorize, _):
            let callback = try await authorize(url, login.callbackScheme(), login.remainingTimeoutMs())
            return try await BlockingCore.run {
                Result { try login.finishWithCallback(callbackUri: callback.absoluteString) }
            }.get()
        }
    }

    func cancel() {
        // A loopback browser tab is outside the app. Connect cancels its
        // shared operation/listener; iOS must also dismiss its system sheet.
        if case .system(_, _, let cancel) = self { cancel() }
    }

    func reopen(_ url: URL) {
        if case .loopback(let open) = self { open(url) }
    }
}
