import SwiftUI
import ZannCoreKit

struct DeviceLanguagePicker: View {
    @EnvironmentObject private var model: AppModel
    private let options = devicePreferenceOptions()
    var body: some View {
        Picker(model.strings("settings.general.language"), selection: Binding(
            get: { model.preferences.language },
            set: { language in model.updatePreferences { $0.language = language } }
        )) {
            Text(model.strings("settings.general.languageSystem")).tag(String?.none)
            ForEach(options.languages, id: \.code) { language in
                Text(language.name).tag(Optional(language.code))
            }
        }
    }
}

/// The same preference options, persistence and biometric controls in both
/// native settings surfaces. Desktop window behaviour stays in SettingsView.
struct DeviceSecuritySections: View {
    @EnvironmentObject private var model: AppModel
    private let options = devicePreferenceOptions()

    var body: some View {
        Section(model.strings("settings.autolock")) {
            choice("settings.autolockAfter", \.autoLockMinutes, options.autoLockMinutes,
                   label: model.strings.minutesLabel)
            Toggle(model.strings("settings.lockOnFocusLoss"), isOn: binding(\.lockOnFocusLoss))
            Toggle(model.strings("settings.lockOnHidden"), isOn: binding(\.lockOnHidden))
        }
        Section(model.strings("settings.clipboard")) {
            choice("settings.clipboardAfter", \.clipboardClearSeconds,
                   options.clipboardClearSeconds, label: model.strings.secondsLabel)
            Toggle(model.strings("settings.clipboardOnLock"), isOn: binding(\.clipboardClearOnLock))
            Toggle(model.strings("settings.clipboardOnExit"), isOn: binding(\.clipboardClearOnExit))
            Toggle(model.strings("settings.clipboardIfUnchanged"), isOn: binding(\.clipboardClearIfUnchanged))
        }
        Section(model.strings("settings.reveal")) {
            choice("settings.revealAfter", \.autoHideRevealSeconds,
                   options.autoHideRevealSeconds, label: model.strings.secondsLabel)
        }
        UnlockPasswordSettings(core: model.browserCore, unlocked: model.isUnlocked, strings: model.strings)
        biometrics
        if let core = model.browserCore {
            ExportSecuritySection(core: core, unlocked: model.isUnlocked, strings: model.strings)
        }
        SettingsFailure()
    }

    private var biometrics: some View {
        let status = model.keystoreStatus
        return Section(model.strings("settings.keystore")) {
            Toggle(biometricLabel, isOn: Binding(
                get: { model.touchIDArmed },
                set: { enabled in Task { await model.setTouchID(enabled) } }
            ))
            .disabled(model.touchIDBusy || (!model.touchIDArmed && (!model.isUnlocked || status?.biometricsAvailable != true)))
            if let status, !status.supported {
                Text(model.strings("errors.keystore_unsupported")).foregroundStyle(.secondary)
            } else if let status, !status.biometricsAvailable {
                Text(model.strings("settings.biometricsUnsupported")).foregroundStyle(.secondary)
            }
        }
    }

    private var biometricLabel: String {
        #if os(iOS)
        model.strings("unlock.biometrics")
        #else
        model.strings("unlock.touchId")
        #endif
    }
    private func choice(_ key: String, _ path: WritableKeyPath<DevicePreferencesFfi, UInt32>,
                        _ values: [UInt32], label: @escaping (UInt32) -> String) -> some View {
        Picker(model.strings(key), selection: binding(path)) {
            ForEach(values, id: \.self) { Text(label($0)).tag($0) }
        }
    }
    private func binding<T>(_ path: WritableKeyPath<DevicePreferencesFfi, T>) -> Binding<T> {
        Binding(get: { model.preferences[keyPath: path] },
                set: { value in model.updatePreferences { $0[keyPath: path] = value } })
    }
}

struct SettingsFailure: View {
    @EnvironmentObject private var model: AppModel
    var body: some View {
        if let error = model.settingsError { Text(error).foregroundStyle(.red) }
    }
}
