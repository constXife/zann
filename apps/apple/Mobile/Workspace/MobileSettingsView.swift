import SwiftUI

struct MobileSettingsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section(model.strings("settings.tabs.general")) { DeviceLanguagePicker() }
                DeviceSecuritySections()
                if let maintenance = model.maintenance {
                    MaintenanceSections(maintenance: maintenance, unlocked: model.isUnlocked, strings: model.strings)
                }
                Section(model.strings("nav.serverAccount")) {
                    Button(model.strings("settings.accounts.signOut"), role: .destructive) {
                        dismiss()
                        Task { await model.logout() }
                    }
                }
            }
            .navigationTitle(model.strings("settings.title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button { dismiss() } label: { Text(model.strings("common.close")).appleTouchTarget() }
                }
            }
        }
    }
}
