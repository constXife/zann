import SwiftUI
import ZannCoreKit

/// The shared `i18n/` catalogue in the system language. Category labels and
/// field labels come from zann-ui-core keys, so they read the same as COSMIC.
struct Strings {
    private let catalogue: TranslationCatalogue

    init(language: String) {
        catalogue = TranslationCatalogue(language: language)
    }

    func callAsFunction(_ key: String) -> String {
        catalogue.get(key: key)
    }

    /// The text for `key` with each `{name}` placeholder filled in.
    func callAsFunction(_ key: String, _ args: [String: String]) -> String {
        args.reduce(catalogue.get(key: key)) { text, arg in
            text.replacingOccurrences(of: "{\(arg.key)}", with: arg.value)
        }
    }

    func fieldLabel(_ key: String) -> String {
        catalogue.fieldLabel(key: key)
    }

    func typeLabel(_ typeID: String) -> String {
        catalogue.typeLabel(typeId: typeID)
    }

    func minutesLabel(_ minutes: UInt32) -> String {
        catalogue.minutesLabel(minutes: minutes)
    }

    func secondsLabel(_ seconds: UInt32) -> String {
        catalogue.secondsLabel(seconds: seconds)
    }

    /// Unlock and sync failures carry an `errors.<kind>` key; other errors,
    /// and kinds without a translation, read as the core's message.
    func message(for failure: Error) -> String {
        let kind: String?
        switch failure as? CoreError {
        case .Unlock(let unlockKind, _)?: kind = unlockKind
        case .Sync(let syncKind, _)?: kind = syncKind
        case .Generator(_, let translationKey, _)?:
            if let translationKey { return self(translationKey) }
            kind = nil
        default: kind = nil
        }
        if let kind {
            let key = "errors.\(kind)"
            let text = self(key)
            if text != key { return text }
        }
        return describe(failure)
    }
}
