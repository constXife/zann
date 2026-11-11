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

    func fieldLabel(_ key: String) -> String {
        catalogue.fieldLabel(key: key)
    }
}
