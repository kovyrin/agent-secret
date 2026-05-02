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
        let isEnabled: Bool

        static func makeAll(viewModel: ApprovalRequestViewModel) -> [Self] {
            [
                Self(
                    decision: .deny,
                    icon: "shield.slash",
                    title: "Deny",
                    subtitle: "Default: Return",
                    role: .secondary,
                    keyboardShortcut: .defaultAction,
                    isEnabled: true
                ),
                Self(
                    decision: .approveOnce,
                    icon: "clock",
                    title: "Allow once",
                    subtitle: viewModel.isExpired ? "Request expired" : "This time only",
                    role: .secondary,
                    keyboardShortcut: nil,
                    isEnabled: !viewModel.isExpired
                ),
                Self(
                    decision: .approveReusable,
                    icon: "checkmark.shield",
                    title: "Allow same command briefly",
                    subtitle: viewModel.isExpired ?
                        "Request expired" :
                        "\(viewModel.compactTimeRemaining) or \(viewModel.reusableUses) uses",
                    role: .primary,
                    keyboardShortcut: nil,
                    isEnabled: !viewModel.isExpired
                )
            ]
        }
    }
#endif
