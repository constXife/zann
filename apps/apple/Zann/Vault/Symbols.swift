import SwiftUI
import ZannCoreKit

/// SF Symbols for the icon names in schemas/ui_categories.json and for item
/// types, like COSMIC maps them onto freedesktop icons.
enum Symbols {
    static func category(_ schemaIcon: String) -> String {
        switch schemaIcon {
        case "grid": return "square.grid.2x2"
        case "key": return "key.fill"
        case "doc": return "note.text"
        case "card": return "creditcard.fill"
        case "person": return "person.crop.circle.fill"
        case "network": return "network"
        case "server": return "server.rack"
        case "list": return "list.bullet"
        case "trash": return "trash"
        default: return "folder"
        }
    }

    static func vault(_ scope: VaultScopeFfi) -> String {
        switch scope {
        case .personal: return "person"
        case .shared: return "person.2"
        }
    }

    static func sync(_ state: SyncIndicatorStateFfi) -> String {
        switch state {
        case .disconnected: return "icloud.slash"
        case .syncing: return "arrow.triangle.2.circlepath"
        case .failed: return "exclamationmark.triangle"
        case .pending: return "arrow.up.circle"
        case .synced: return "checkmark.circle"
        }
    }

    static func item(_ typeID: String) -> String {
        switch typeID {
        case "login": return "key.fill"
        case "note": return "note.text"
        case "card": return "creditcard.fill"
        case "identity": return "person.crop.circle.fill"
        case "api": return "network"
        default: return "list.bullet"
        }
    }

    static func tint(_ typeID: String) -> Color {
        switch typeID {
        case "login": return .blue
        case "note": return .yellow
        case "card": return .green
        case "identity": return .orange
        case "api": return .purple
        default: return .gray
        }
    }
}

/// The rounded icon tile Passwords-style lists and headers use.
struct ItemIcon: View {
    let typeID: String
    var size: CGFloat = 28
    var faviconRgba: Data?
    var loginTitle: String?

    private var favicon: CGImage? {
        guard let faviconRgba, faviconRgba.count == 16 * 16 * 4,
              let provider = CGDataProvider(data: faviconRgba as CFData) else { return nil }
        return CGImage(width: 16, height: 16, bitsPerComponent: 8, bitsPerPixel: 32,
                       bytesPerRow: 64, space: CGColorSpaceCreateDeviceRGB(),
                       bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.last.rawValue),
                       provider: provider, decode: nil, shouldInterpolate: true, intent: .defaultIntent)
    }

    var body: some View {
        if let favicon {
            Image(decorative: favicon, scale: 1)
                .resizable().scaledToFit().padding(size * 0.12)
                .frame(width: size, height: size)
        } else if typeID == "login", let initial = loginTitle?.first(where: { !$0.isWhitespace }) {
            Text(String(initial).localizedUppercase.prefix(1))
                .font(.system(size: size * 0.58, weight: .medium))
                .foregroundStyle(.primary)
                .frame(width: size, height: size)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: size * 0.24, style: .continuous))
        } else {
            RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
            .fill(Symbols.tint(typeID).gradient)
            .frame(width: size, height: size)
            .overlay {
                Image(systemName: Symbols.item(typeID))
                    .font(.system(size: size * 0.5, weight: .semibold))
                    .foregroundStyle(.white)
            }
        }
    }
}
