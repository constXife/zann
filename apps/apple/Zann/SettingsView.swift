import SwiftUI
import ZannCoreKit

/// The device settings COSMIC also offers, as a native Settings window (⌘,).
/// zann-ui-core supplies the choices and their labels; every change goes
/// through `AppModel.updatePreferences`, which saves before applying it.
struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    private let options = devicePreferenceOptions()

    var body: some View {
        TabView {
            general
                .tabItem { Label(model.strings("settings.tabs.general"), systemImage: "gearshape") }
            security
                .tabItem { Label(model.strings("settings.tabs.security"), systemImage: "lock") }
        }
        .frame(width: 520)
    }

    private var general: some View {
        Form {
            Picker(model.strings("settings.general.language"), selection: binding(\.language)) {
                Text(model.strings("settings.general.languageSystem")).tag(String?.none)
                ForEach(options.languages, id: \.code) { language in
                    Text(language.name).tag(Optional(language.code))
                }
            }
            failure
        }
        .formStyle(.grouped)
    }

    private var security: some View {
        Form {
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
                Toggle(
                    model.strings("settings.clipboardIfUnchanged"),
                    isOn: binding(\.clipboardClearIfUnchanged)
                )
            }
            Section(model.strings("settings.reveal")) {
                choice("settings.revealAfter", \.autoHideRevealSeconds,
                       options.autoHideRevealSeconds, label: model.strings.secondsLabel)
            }
            failure
        }
        .formStyle(.grouped)
    }

    @ViewBuilder private var failure: some View {
        if let error = model.settingsError {
            Text(error).foregroundStyle(.red)
        }
    }

    private func choice(
        _ titleKey: String,
        _ keyPath: WritableKeyPath<DevicePreferencesFfi, UInt32>,
        _ values: [UInt32],
        label: @escaping (UInt32) -> String
    ) -> some View {
        Picker(model.strings(titleKey), selection: binding(keyPath)) {
            ForEach(values, id: \.self) { value in
                Text(label(value)).tag(value)
            }
        }
    }

    private func binding<T>(_ keyPath: WritableKeyPath<DevicePreferencesFfi, T>) -> Binding<T> {
        Binding(
            get: { model.preferences[keyPath: keyPath] },
            set: { value in model.updatePreferences { $0[keyPath: keyPath] = value } }
        )
    }
}
