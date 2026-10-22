#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    /// Semantic colors adapt to appearance and the system's accessibility contrast.
    enum ApprovalPanelTheme {
        static let surface = Color(nsColor: .windowBackgroundColor)
        static let raised = Color(nsColor: .controlBackgroundColor)
        static let sunken = Color(nsColor: .underPageBackgroundColor)
        static let border = Color(nsColor: .separatorColor)
        static let accent = Color(nsColor: .systemGreen)
    }
#endif
