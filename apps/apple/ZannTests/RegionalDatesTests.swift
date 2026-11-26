import XCTest
#if os(iOS)
@testable import ZannMobile
#else
@testable import Zann
#endif

final class RegionalDatesTests: XCTestCase {
    func testRangeLabelFollowsRegionalDateOrderAndIncludesTheLastDay() throws {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = try XCTUnwrap(TimeZone(identifier: "Asia/Tbilisi"))
        let from = try XCTUnwrap(calendar.date(from: DateComponents(year: 2026, month: 11, day: 25)))
        let through = try XCTUnwrap(calendar.date(from: DateComponents(year: 2026, month: 12, day: 3)))
        let range = DateInterval(start: from, end: try XCTUnwrap(calendar.dateInterval(of: .day, for: through)).end)
        let single = try XCTUnwrap(calendar.dateInterval(of: .day, for: from))
        let labels = ["en_US", "en_GB", "ru_RU"].map { identifier in
            let locale = Locale(identifier: identifier)
            let reference = DateFormatter()
            reference.locale = locale
            reference.calendar = calendar
            reference.timeZone = calendar.timeZone
            reference.dateStyle = .short
            let label = RegionalDates(locale: locale, calendar: calendar).rangeLabel(range)
            XCTAssertEqual(label, reference.string(from: from) + " – " + reference.string(from: through))
            XCTAssertEqual(RegionalDates(locale: locale, calendar: calendar).rangeLabel(single),
                           reference.string(from: from))
            return label
        }
        XCTAssertNotEqual(labels[0], labels[1])
    }

    func testTimestampsUseLocalDayAndRegionalClockWithOrWithoutFractions() throws {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = try XCTUnwrap(TimeZone(identifier: "Asia/Tbilisi"))
        let day = try XCTUnwrap(calendar.date(from: DateComponents(year: 2026, month: 11, day: 26)))
        let instant = try XCTUnwrap(calendar.date(byAdding: .minute, value: 30, to: day))
        for identifier in ["en_US", "en_GB", "ru_RU"] {
            let locale = Locale(identifier: identifier)
            let dates = RegionalDates(locale: locale, calendar: calendar)
            let reference = DateFormatter()
            reference.locale = locale
            reference.calendar = calendar
            reference.timeZone = calendar.timeZone
            reference.dateStyle = .short
            reference.timeStyle = .short
            let full = reference.string(from: instant)
            reference.dateStyle = .none
            for value in ["2026-11-25T20:30:00Z", "2026-11-25T22:30:00.123456789+02:00"] {
                XCTAssertEqual(dates.timestamp(value), full)
                XCTAssertEqual(dates.timestamp(value, omittingDateOn: day), reference.string(from: instant))
                XCTAssertEqual(dates.timestamp(value, omittingDateOn: day.addingTimeInterval(-1)), full)
            }
            XCTAssertNil(dates.timestamp("unavailable"))
        }
    }
}
