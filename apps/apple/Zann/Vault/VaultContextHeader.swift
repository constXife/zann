import SwiftUI
import ZannCoreKit

/// Server/account context first; vault navigation belongs to that context.
struct VaultContextHeader: View {
    @ObservedObject var vault: VaultModel
    let strings: Strings
    @EnvironmentObject private var app: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                if vault.storages.isEmpty && vault.awaitingFirstSync {
                    Label(strings("sync.firstSyncTitle"), systemImage: "server.rack")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } else {
                    #if os(iOS)
                    mobileStorageMenu
                    #else
                    Picker(strings("nav.serverAccount"), selection: storageSelection) {
                        if vault.storageID == nil { Text(strings("nav.serverAccount")).tag(String?.none) }
                        ForEach(vault.storages, id: \.id) { storage in
                            Label(storage.displayName, systemImage: storage.serverUrl == nil ? "desktopcomputer" : "server.rack")
                                .lineLimit(1)
                                .tag(Optional(storage.id))
                        }
                    }
                    .pickerStyle(.menu)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .appleTouchTarget()
                    .labelsHidden()
                    .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)
                    .disabled(vault.editor != nil || vault.switching)
                    .help(vault.storages.first(where: { $0.id == vault.storageID })?.serverUrl ?? strings("nav.serverAccount"))
                    #endif
                }
                if let indicator = vault.indicator {
                    SyncIndicatorButton(
                        indicator: indicator, syncState: vault.syncState,
                        error: vault.syncError, busy: app.busy || vault.switching, strings: strings,
                        syncing: vault.syncing && vault.canSync,
                        recovery: SyncRecoveryActions(vault: vault, strings: strings),
                        onRefresh: { await vault.refreshSyncState() },
                        onSync: { await vault.sync() },
                        onReconnect: { await app.reconnectServer() }
                    )
                    .buttonStyle(.borderless)
                    .frame(minWidth: 24, minHeight: 24)
                    .appleTouchTarget()
                }
            }
            if vault.vaults.count > 1 {
                #if os(iOS)
                mobileVaultMenu
                #else
                Picker(strings("nav.vaults"), selection: vaultSelection) {
                    ForEach(vault.vaults, id: \.id) { summary in
                        Label("\(summary.name) (\(summary.itemCount))", systemImage: Symbols.vault(summary.scope))
                            .lineLimit(1)
                            .tag(Optional(summary.id))
                    }
                }
                .pickerStyle(.menu)
                .lineLimit(1)
                .truncationMode(.middle)
                .appleTouchTarget()
                .labelsHidden()
                .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)
                .disabled(vault.editor != nil || vault.switching || !vault.contextReady)
                #endif
            } else if let summary = vault.vaults.first(where: { $0.id == vault.vaultID }) {
                Label(summary.name, systemImage: Symbols.vault(summary.scope))
                    .lineLimit(1)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
    }

    #if os(iOS)
    /// An explicit native menu label can truncate within a narrow column;
    /// Picker's generated selected-value label ignores that width on iPad.
    private var mobileStorageMenu: some View {
        Menu {
            ForEach(vault.storages, id: \.id) { storage in
                Button { storageSelection.wrappedValue = storage.id } label: {
                    Label(storage.displayName, systemImage: storage.id == vault.storageID ? "checkmark" : "server.rack")
                }
            }
        } label: {
            if let storage = vault.storages.first(where: { $0.id == vault.storageID }) {
                menuLabel(storage.displayName, icon: storage.serverUrl == nil ? "desktopcomputer" : "server.rack")
            } else {
                menuLabel(strings("nav.serverAccount"), icon: "server.rack")
            }
        }
        .buttonStyle(.borderless)
        .disabled(vault.editor != nil || vault.switching)
        .accessibilityHint(strings("nav.serverAccount"))
        .accessibilityIdentifier("workspace.storage")
    }

    private var mobileVaultMenu: some View {
        Menu {
            ForEach(vault.vaults, id: \.id) { summary in
                Button { vaultSelection.wrappedValue = summary.id } label: {
                    Label("\(summary.name) (\(summary.itemCount))",
                          systemImage: summary.id == vault.vaultID ? "checkmark" : Symbols.vault(summary.scope))
                }
            }
        } label: {
            if let summary = vault.vaults.first(where: { $0.id == vault.vaultID }) {
                menuLabel(summary.name, icon: Symbols.vault(summary.scope))
            } else {
                menuLabel(strings("nav.vaults"), icon: "folder")
            }
        }
        .buttonStyle(.borderless)
        .disabled(vault.editor != nil || vault.switching || !vault.contextReady)
        .accessibilityHint(strings("nav.vaults"))
        .accessibilityIdentifier("workspace.vault")
    }

    private func menuLabel(_ title: String, icon: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: icon).accessibilityHidden(true)
            Text(title)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)
            Image(systemName: "chevron.down").font(.caption).accessibilityHidden(true)
        }
        .appleTouchTarget()
    }
    #endif

    private var storageSelection: Binding<String?> {
        Binding(get: { vault.storageID }, set: { id in if let id { Task { await vault.selectStorage(id) } } })
    }

    private var vaultSelection: Binding<String?> {
        Binding(get: { vault.vaultID }, set: { id in
            if let id { Task { await vault.selectVault(id) } }
        })
    }
}
