import SwiftUI

struct UpdatedRangeControl: View {
    @ObservedObject var vault: VaultModel
    let strings: Strings
    @State private var editing = false
    @State private var firstDay = Date()
    @State private var lastDay = Date()
    @Environment(\.calendar) private var calendar

    static func interval(from first: Date, through last: Date, calendar: Calendar) -> DateInterval? {
        let start = calendar.startOfDay(for: first)
        guard let end = calendar.dateInterval(of: .day, for: last)?.end, start < end else { return nil }
        return DateInterval(start: start, end: end)
    }

    var body: some View {
        HStack {
            Button {
                firstDay = vault.updatedRange?.start ?? calendar.startOfDay(for: Date())
                lastDay = vault.updatedRange.map { $0.end.addingTimeInterval(-1) } ?? firstDay
                editing = true
            } label: {
                Label {
                    if let range = vault.updatedRange {
                        Text(verbatim: RegionalDates(calendar: calendar).rangeLabel(range))
                    } else {
                        Text(strings("items.updatedRange"))
                    }
                } icon: { Image(systemName: "calendar") }
            }
            .accessibilityHint(strings("items.updatedRange"))
            .popover(isPresented: $editing) {
                VStack(alignment: .leading, spacing: 12) {
                    Text(strings("items.updatedRange")).font(.headline)
                    DatePicker(strings("items.dateFrom"), selection: $firstDay, displayedComponents: .date)
                    DatePicker(strings("items.dateThrough"), selection: $lastDay, displayedComponents: .date)
                    HStack {
                        Button(strings("common.cancel")) { editing = false }
                        Spacer()
                        Button(strings("items.applyDates")) {
                            guard let range = Self.interval(from: firstDay, through: lastDay, calendar: calendar) else { return }
                            vault.updatedRange = range
                            editing = false
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(Self.interval(from: firstDay, through: lastDay, calendar: calendar) == nil)
                    }
                }
                .environment(\.locale, Locale.autoupdatingCurrent)
                .padding().frame(minWidth: 260)
            }
            if vault.updatedRange != nil {
                Button { vault.updatedRange = nil } label: {
                    Image(systemName: "xmark.circle.fill")
                }
                .accessibilityLabel(strings("items.clearDates"))
                .help(strings("items.clearDates"))
            }
            Spacer()
        }
        .padding(.horizontal).padding(.vertical, 4)
        .background(.bar)
    }
}
