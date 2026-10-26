#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    /// Opaque surfaces adapt to appearance; semantic text and borders retain system contrast.
    enum ApprovalPanelTheme {
        static let surface = Color(nsColor: .controlBackgroundColor)
        static let raised = Color(nsColor: .controlBackgroundColor)
        private static let lightSunkenWhite: CGFloat = 0.965
        private static let darkSunkenWhite: CGFloat = 0.16
        static let sunken = Color(nsColor: NSColor(name: nil) { appearance in
            let dark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            return NSColor(white: dark ? darkSunkenWhite : lightSunkenWhite, alpha: 1)
        })
        static let border = Color(nsColor: .separatorColor)
        private static let lightRed: CGFloat = 0.094
        private static let lightGreen: CGFloat = 0.514
        private static let lightBlue: CGFloat = 0.290
        private static let darkRed: CGFloat = 0.239
        private static let darkGreen: CGFloat = 0.745
        private static let darkBlue: CGFloat = 0.447

        static let allowForeground = Color(nsColor: .textBackgroundColor)
        static let allowBackground = Color(nsColor: NSColor(name: nil) { appearance in
            if appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua {
                return NSColor(srgbRed: darkRed, green: darkGreen, blue: darkBlue, alpha: 1)
            }
            return NSColor(srgbRed: lightRed, green: lightGreen, blue: lightBlue, alpha: 1)
        })
        static let accent = Color(nsColor: .systemGreen)
    }
#endif
