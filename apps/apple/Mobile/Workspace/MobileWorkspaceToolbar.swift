import SwiftUI

struct MobileWorkspaceToolbar: ToolbarContent {
    enum Region { case all, sidebar, list, detail }
    @ObservedObject var vault: VaultModel
    @ObservedObject var navigation: MobileNavigation
    @ObservedObject var app: AppModel
    let region: Region
    var showingDetail = false

    var body: some ToolbarContent {
        ToolbarItemGroup(placement: .navigationBarTrailing) {
            if region == .all || region == .list {
                if showingDetail { edit } else { create }
                sync
            }
            if region == .detail { edit }
            if region == .all || region == .sidebar {
                Button { Task { await app.lock() } } label: {
                    Label(app.strings("common.lock"), systemImage: "lock").appleTouchTarget()
                }.accessibilityIdentifier("workspace.lock")
                Button { navigation.settingsPresented = true } label: {
                    Label(app.strings("settings.title"), systemImage: "gearshape").appleTouchTarget()
                }.accessibilityIdentifier("workspace.settings")
            }
        }
    }

    private var create: some View {
        Menu {
            ForEach(ItemEditorModel.typeIDs, id: \.self) { type in
                Button(app.strings("types.\(type)")) { vault.startCreating(typeID: type) }
                    .accessibilityIdentifier("create.type.\(type)")
            }
        } label: {
            Label(app.strings("common.create"), systemImage: "plus").appleTouchTarget()
        }
        .accessibilityIdentifier("workspace.create")
        .disabled(vault.switching || !vault.contextReady || vault.vaultID == nil)
    }

    private var edit: some View {
        Button { Task { await vault.startEditing() } } label: {
            Label(app.strings("common.edit"), systemImage: "pencil").appleTouchTarget()
        }.disabled(!vault.canEdit).accessibilityIdentifier("workspace.edit")
    }

    @ViewBuilder private var sync: some View {
        if let indicator = vault.indicator {
            SyncIndicatorButton(indicator: indicator, syncState: vault.syncState,
                error: vault.syncError, busy: app.busy || vault.switching, strings: app.strings,
                syncing: vault.syncing && vault.canSync,
                recovery: SyncRecoveryActions(vault: vault, strings: app.strings),
                onRefresh: { await vault.refreshSyncState() }, onSync: { await vault.sync() },
                onReconnect: { await app.reconnectServer() })
        }
    }
}
