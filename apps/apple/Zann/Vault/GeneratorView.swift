import SwiftUI
import ZannCoreKit

/// Controls and field assignment only. Defaults, bounds, validation, word
/// selection and entropy all come from zann-ui-core through the FFI adapter.
struct GeneratorView: View {
    let strings: Strings
    let onGenerated: (String) -> Void
    private let defaults: GeneratorDefaultsFfi
    @State private var password: PasswordOptionsFfi
    @State private var passphrase: PassphraseOptionsFfi
    @State private var passphraseMode = false
    @State private var error: String?

    init(strings: Strings, onGenerated: @escaping (String) -> Void) {
        self.strings = strings
        self.onGenerated = onGenerated
        let defaults = generatorDefaults()
        self.defaults = defaults
        _password = State(initialValue: defaults.password)
        _passphrase = State(initialValue: defaults.passphrase)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(strings("create.generatorTitle")).font(.headline)
            Picker(strings("create.generatorTitle"), selection: $passphraseMode) {
                Text(strings("create.generatorPassword")).tag(false)
                Text(strings("create.generatorPassphrase")).tag(true)
            }
            .pickerStyle(.segmented)
            if passphraseMode {
                Stepper("\(strings("create.generatorWords")): \(passphrase.wordCount)",
                        value: $passphrase.wordCount, in: defaults.minWords...defaults.maxWords)
                Picker(strings("create.generatorSeparator"), selection: $passphrase.separator) {
                    ForEach(defaults.separators, id: \.self) { separator in
                        Text(separator == .space ? strings("create.generatorSpace") : wordSeparatorText(separator: separator))
                            .tag(separator)
                    }
                }
                Toggle(strings("create.generatorCapitalize"), isOn: $passphrase.capitalize)
                Toggle(strings("create.generatorAddDigit"), isOn: $passphrase.includeDigit)
            } else {
                Stepper("\(strings("create.generatorLength")): \(password.length)",
                        value: $password.length, in: defaults.minPasswordLength...defaults.maxPasswordLength)
                Toggle(strings("create.generatorLower"), isOn: $password.lowercase)
                Toggle(strings("create.generatorUpper"), isOn: $password.uppercase)
                Toggle(strings("create.generatorDigits"), isOn: $password.digits)
                Toggle(strings("create.generatorSymbols"), isOn: $password.symbols)
                Toggle(strings("create.generatorAvoidAmbiguous"), isOn: $password.avoidAmbiguous)
            }
            if let error {
                Text(error).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }
            Button(strings("create.generateSecret"), action: generate)
                .buttonStyle(.borderedProminent)
        }
        .padding(16)
        .frame(width: 320)
    }

    private func generate() {
        let result = Result {
            if passphraseMode {
                return try generatePassphrase(options: passphrase)
            }
            return try generatePassword(options: password)
        }
        switch result {
        case .success(let value):
            error = nil
            onGenerated(value)
        case .failure(let failure):
            error = strings.message(for: failure)
        }
    }
}
