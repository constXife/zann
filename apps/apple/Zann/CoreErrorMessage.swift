import Foundation
import ZannCoreKit

/// The core's own message for an error, without the enum wrapping.
func describe(_ error: Error) -> String {
    guard let error = error as? CoreError else {
        return error.localizedDescription
    }
    switch error {
    case .Browser(_, let message):
        return message
    case .Locked:
        return "The vault is locked."
    case .Cancelled:
        return "Operation cancelled."
    case .DeadlineExceeded:
        return "The operation timed out."
    case .InvalidArgument(let message), .Service(let message), .Unimplemented(let message):
        return message
    case .Unlock(_, let message), .Sync(_, let message), .Generator(_, _, let message):
        return message
    case .Session(_, let message), .Oidc(_, let message), .Draft(_, _, let message):
        return message
    }
}
