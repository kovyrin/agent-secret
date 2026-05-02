import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelDecisionButtonSpec: Equatable {
        let decision: ApprovalDecisionKind
        let icon: String
        let title: String
        let subtitle: String
        let role: ApprovalPanelDecisionButtonRole
        let keyboardShortcut: ApprovalPanelKeyboardShortcut?

        static func makeAll(viewModel: ApprovalRequestViewModel) -> [Self] {
            [
                Self(
                    decision: .deny,
                    icon: "shield.slash",
                    title: "Deny",
                    subtitle: "Default: Return",
                    role: .secondary,
                    keyboardShortcut: .defaultAction
                ),
                Self(
                    decision: .approveOnce,
                    icon: "clock",
                    title: "Allow once",
                    subtitle: "This time only",
                    role: .secondary,
                    keyboardShortcut: nil
                ),
                Self(
                    decision: .approveReusable,
                    icon: "checkmark.shield",
                    title: "Allow same command briefly",
                    subtitle: "\(viewModel.compactTimeRemaining) or \(viewModel.reusableUses) uses",
                    role: .primary,
                    keyboardShortcut: nil
                )
            ]
        }
    }
#endif
