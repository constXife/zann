import SwiftUI
import ZannCoreKit

/// First vault screen: the unlocked item list. The three-pane layout over
/// zann-ui-core projections replaces it in the next slice.
struct VaultView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        NavigationStack {
            Group {
                if model.items.isEmpty {
                    ContentUnavailableNotice(title: "No items yet", message: "This vault is empty.")
                } else {
                    List(model.items, id: \.id) { item in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.title)
                            if !item.path.isEmpty {
                                Text(item.path).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Zann")
            .toolbar {
                Button {
                    Task { await model.lock() }
                } label: {
                    Label("Lock", systemImage: "lock")
                }
                .help("Lock (⌘L)")
            }
        }
    }
}
