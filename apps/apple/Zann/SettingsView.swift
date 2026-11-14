import SwiftUI
import ZannCoreKit

/// Shared device policies are saved through AppModel; macOS-only Dock
/// preferences are owned and persisted by DockVisibility.
struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var dock: DockVisibility
    private let options = devicePreferenceOptions()

    var body: some View {
        TabView {
            general
                .fittedToContent()
                .tabItem { Label(model.strings("settings.tabs.general"), systemImage: "gearshape") }
            security
                .fittedToContent()
                .tabItem { Label(model.strings("settings.tabs.security"), systemImage: "lock") }
            Form {
                BrowserPairingsView(core: model.browserCore, strings: model.strings)
            }
            .formStyle(.grouped)
            .frame(height: 420)
            .tabItem { Label(model.strings("browser.title"), systemImage: "globe") }
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
            Section(model.strings("settings.general.behavior")) {
                Toggle(model.strings("settings.general.hideDockWhenClosed"),
                       isOn: $dock.hideWhenClosed)
                Text(model.strings("settings.general.hideDockWhenClosedHelp"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
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
            touchID
            failure
        }
        .formStyle(.grouped)
    }

    /// Arming wraps the master key the unlocked core holds, so the toggle
    /// works only while the vault is open.
    @ViewBuilder private var touchID: some View {
        let status = model.keystoreStatus
        Section(model.strings("settings.keystore")) {
            Toggle(model.strings("unlock.touchId"), isOn: Binding(
                get: { model.touchIDArmed },
                set: { enabled in Task { await model.setTouchID(enabled) } }
            ))
            // Turning it off stays possible without Touch ID, to revoke it.
            .disabled(
                model.touchIDBusy
                    || (!model.touchIDArmed
                        && (!model.isUnlocked || status?.biometricsAvailable != true))
            )
            if let status, !status.supported {
                Text(model.strings("errors.keystore_unsupported")).foregroundStyle(.secondary)
            } else if let status, !status.biometricsAvailable {
                Text(model.strings("settings.biometricsUnsupported")).foregroundStyle(.secondary)
            }
        }
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

private extension View {
    /// A grouped form scrolls and takes any height it is given; in Settings
    /// each tab should instead size the window to its own rows.
    func fittedToContent() -> some View {
        scrollDisabled(true).fixedSize(horizontal: false, vertical: true)
    }
}
