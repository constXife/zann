import SwiftUI
import UIKit

struct MobileVaultView: View {
    @ObservedObject var vault: VaultModel
    @EnvironmentObject private var app: AppModel
    @Environment(\.horizontalSizeClass) private var sizeClass
    @Environment(\.dynamicTypeSize) private var textSize
    @StateObject private var navigation = MobileNavigation()
    @State private var columns = NavigationSplitViewVisibility.all

    var body: some View {
        let tablet = UIDevice.current.userInterfaceIdiom == .pad
        Group {
            if navigation.layout == .columns {
                NavigationSplitView(columnVisibility: $columns) {
                    context.toolbar { actions(.sidebar) }
                        .navigationSplitViewColumnWidth(min: 180, ideal: 220, max: 300)
                } content: {
                    items.toolbar { actions(.list) }
                        .navigationSplitViewColumnWidth(min: 280, ideal: 340, max: 480)
                } detail: {
                    detail.toolbar { actions(.detail) }
                }.navigationSplitViewStyle(.balanced)
            } else {
                NavigationStack(path: $navigation.path) {
                    context.toolbar { actions(.all) }
                        .navigationDestination(for: MobileNavigation.Route.self) { route in
                            switch route {
                            case .items: items.toolbar { actions(.all) }
                            case .detail: detail.toolbar { actions(.all, detail: true) }
                            }
                        }
                }
            }
        }
        .accessibilityIdentifier(navigation.layout == .columns ? "workspace.columns" : "workspace.stack")
        .onGeometryChange(for: MobileNavigation.Layout.self) { proxy in
            MobileNavigation.layout(width: proxy.size.width, regular: sizeClass == .regular,
                                    tablet: tablet, accessibilityText: textSize.isAccessibilitySize)
        } action: { navigation.resize(to: $0) }
        .fullScreenCover(item: editor) { editor in
            ItemEditorView(editor: editor, vault: vault, strings: app.strings)
                .environmentObject(app)
                .dynamicTypeSize(textSize)
                .interactiveDismissDisabled(editor.busy)
        }
        .sheet(isPresented: $navigation.settingsPresented, onDismiss: { app.maintenance?.dismissed() }) {
            MobileSettingsView().environmentObject(app).dynamicTypeSize(textSize)
        }
        .onChange(of: vault.selectedItemID) { navigation.selectionChanged($0) }
        .onChange(of: vault.vaultID) { _ in navigation.contextChanged() }
        .onChange(of: vault.storageID) { _ in navigation.contextChanged() }
        .onChange(of: vault.query) { _ in navigation.listAnchor = nil; app.noteActivity() }
        .onChange(of: vault.categoryID) { _ in navigation.listAnchor = nil }
        .onChange(of: vault.folder) { _ in navigation.listAnchor = nil }
    }

    private var context: some View {
        MobileContextView(vault: vault, strings: app.strings, showItems: navigation.showItems)
    }
    private var items: some View {
        MobileItemList(vault: vault, navigation: navigation, strings: app.strings) { id in
            vault.select(id)
            navigation.showDetail()
        }
    }
    private var detail: some View {
        ItemDetailView(vault: vault, strings: app.strings, preferences: app.preferences, revealAll: false)
            .navigationTitle(vault.detail?.title ?? app.strings("items.details"))
            .navigationBarTitleDisplayMode(.inline)
    }
    private func actions(_ region: MobileWorkspaceToolbar.Region, detail: Bool = false) -> some ToolbarContent {
        MobileWorkspaceToolbar(vault: vault, navigation: navigation, app: app, region: region, showingDetail: detail)
    }
    private var editor: Binding<ItemEditorModel?> {
        Binding(get: { vault.editor }, set: { if $0 == nil { vault.cancelEditing() } })
    }
}
