import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    struct ApprovalPanelDecisionButtonSpec: Equatable {
        let decision: ApprovalDecisionKind
        let icon: String
        let title: String
        let subtitle: String
        let role: ApprovalPanelDecisionButtonRole
        let keyboardShortcut: KeyboardShortcut?
        let isEnabled: Bool

        static func makeAll(viewModel: ApprovalRequestViewModel) -> [Self] {
            var specs: [Self] = [
                Self(
                    decision: .deny,
                    icon: "shield.slash",
                    title: "Deny",
                    subtitle: "Esc",
                    role: .secondary,
                    keyboardShortcut: .cancelAction,
                    isEnabled: true
                ),
                Self(
                    decision: .approveOnce,
                    icon: "clock",
                    title: "Allow once",
                    subtitle: viewModel.isExpired ? "Request expired" : "Click to approve",
                    role: .secondary,
                    keyboardShortcut: nil,
                    isEnabled: !viewModel.isExpired
                )
            ]
            if viewModel.allowsReusableApproval {
                specs.append(
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
                )
            }
            return specs
        }
    }
#endif
