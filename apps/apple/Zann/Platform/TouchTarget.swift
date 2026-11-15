import SwiftUI

extension View {
    /// Apply to the label inside a control, so its hit and accessibility
    /// regions include the padding rather than only the surrounding layout.
    @ViewBuilder func appleTouchTarget() -> some View {
        #if os(iOS)
        frame(minWidth: 44, minHeight: 44)
            .contentShape(Rectangle())
        #else
        self
        #endif
    }
}
