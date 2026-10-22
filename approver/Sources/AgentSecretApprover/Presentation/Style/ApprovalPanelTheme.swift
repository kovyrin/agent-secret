#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    /// Semantic colors adapt to appearance and the system's accessibility contrast.
    enum ApprovalPanelTheme {
        static let surface = Color(nsColor: .windowBackgroundColor)
        static let raised = Color(nsColor: .controlBackgroundColor)
        static let sunken = Color(nsColor: .underPageBackgroundColor)
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
