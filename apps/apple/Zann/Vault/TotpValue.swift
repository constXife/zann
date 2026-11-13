import SwiftUI
import ZannCoreKit

struct TotpValue: View {
    let params: TotpParamsFfi
    let label: String
    let copied: Bool
    let strings: Strings
    let copyFeedback: String
    let accessoryWidth: CGFloat
    let onCopy: (String) -> Void

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { _ in
            if let code = try? generateTotp(params: params) {
                HStack(spacing: 8) {
                    CopyValueButton(
                        value: grouped(code.code), fieldLabel: label,
                        font: .title3.monospaced(), singleLine: true,
                        copied: copied, strings: strings, copyFeedback: copyFeedback,
                        onCopy: { onCopy(code.code) }
                    )
                    TotpCountdown(remaining: code.remainingSeconds, period: code.period)
                        .frame(width: accessoryWidth)
                }
            } else {
                Text(strings("totp.error"))
                    .foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private func grouped(_ code: String) -> String {
        let split = code.index(code.startIndex, offsetBy: code.count / 2)
        return "\(code[..<split]) \(code[split...])"
    }
}

private struct TotpCountdown: View {
    let remaining: UInt32
    let period: UInt32

    var body: some View {
        let fraction = period > 0 ? Double(remaining) / Double(period) : 0
        let ending = remaining <= 5
        ZStack {
            Circle().stroke(Color.secondary.opacity(0.25), lineWidth: 2)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(ending ? Color.orange : Color.secondary, style: StrokeStyle(lineWidth: 2, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: remaining)
        }
        .frame(width: 14, height: 14)
        .help("\(remaining)s")
        .accessibilityLabel("\(remaining)s")
    }
}
