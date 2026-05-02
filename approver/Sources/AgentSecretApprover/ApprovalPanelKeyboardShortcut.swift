import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    enum ApprovalPanelKeyboardShortcut: Equatable {
        case defaultAction

        var keyboardShortcut: KeyboardShortcut {
            switch self {
            case .defaultAction:
                .defaultAction
            }
        }
    }
#endif
