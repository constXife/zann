import SwiftUI
import ZannCoreKit

/// Shared device policies are saved through AppModel; macOS-only Dock
/// preferences are owned and persisted by DockVisibility.
struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var dock: DockVisibility

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
            DeviceLanguagePicker()
            Section(model.strings("settings.general.behavior")) {
                Toggle(model.strings("settings.general.hideDockWhenClosed"),
                       isOn: $dock.hideWhenClosed)
                Text(model.strings("settings.general.hideDockWhenClosedHelp"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            SettingsFailure()
        }
        .formStyle(.grouped)
    }

    private var security: some View {
        Form { DeviceSecuritySections() }.formStyle(.grouped)
    }

}

private extension View {
    /// A grouped form scrolls and takes any height it is given; in Settings
    /// each tab should instead size the window to its own rows.
    func fittedToContent() -> some View {
        scrollDisabled(true).fixedSize(horizontal: false, vertical: true)
    }
}
