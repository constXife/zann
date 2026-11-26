import Foundation

/// System regional preferences for dates shown in the native interface.
struct RegionalDates {
    var locale: Locale = .autoupdatingCurrent
    var calendar: Calendar = .autoupdatingCurrent

    private func formatter(date: DateFormatter.Style, time: DateFormatter.Style) -> DateFormatter {
        let formatter = DateFormatter()
        formatter.locale = locale
        formatter.calendar = calendar
        formatter.timeZone = calendar.timeZone
        formatter.dateStyle = date
        formatter.timeStyle = time
        return formatter
    }

    func rangeLabel(_ range: DateInterval) -> String {
        let shortDate = formatter(date: .short, time: .none)
        let lastDay = range.end.addingTimeInterval(-1)
        let first = shortDate.string(from: range.start)
        return calendar.isDate(range.start, inSameDayAs: lastDay)
            ? first : first + " – " + shortDate.string(from: lastDay)
    }

    /// RFC 3339 permits both whole and fractional seconds. Compare local
    /// calendar days after parsing the offset carried by the timestamp.
    func timestamp(_ value: String, omittingDateOn day: Date? = nil) -> String? {
        let parser = Date.ISO8601FormatStyle(includingFractionalSeconds: value.contains("."))
        guard let date = try? parser.parse(value) else { return nil }
        let sameDay = day.map { calendar.isDate(date, inSameDayAs: $0) } == true
        return formatter(date: sameDay ? .none : .short, time: .short).string(from: date)
    }
}
