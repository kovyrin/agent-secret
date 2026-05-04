import Foundation

#if canImport(AppKit)
    import AppKit

    final class ApprovalPanelWindow: NSPanel {
        override var canBecomeKey: Bool {
            true
        }

        override var canBecomeMain: Bool {
            true
        }
    }
#endif
