import SwiftUI

/// Navigation and scroll bookmarks only; vault selection and drafts stay in
/// VaultModel. Replacing columns with a stack never replaces that model.
@MainActor
final class MobileNavigation: ObservableObject {
    enum Layout: Equatable { case stack, columns }
    enum Route: Hashable { case items, detail }

    @Published var path: [Route] = [.items]
    @Published var settingsPresented = false
    @Published private(set) var layout = Layout.stack
    var listAnchor: String?

    nonisolated static func layout(width: CGFloat, regular: Bool, tablet: Bool, accessibilityText: Bool) -> Layout {
        tablet && regular && width >= 900 && !accessibilityText ? .columns : .stack
    }

    func resize(to layout: Layout) { self.layout = layout }
    func showItems() { path = [.items] }
    func showDetail() { path = [.items, .detail] }
    func selectionChanged(_ id: String?) {
        if id != nil { showDetail() }
        else if path.last == .detail { showItems() }
    }
    func contextChanged() { listAnchor = nil; showItems() }
}
