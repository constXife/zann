import SwiftUI

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
        case "list": return "list.bullet"
        case "trash": return "trash"
        default: return "folder"
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

    var body: some View {
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
