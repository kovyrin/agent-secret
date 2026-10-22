import Foundation

#if canImport(SwiftUI)
    import SwiftUI

    /// The two visible actions, derived from the scope currently shown to the operator.
    struct ApprovalPanelDecisionButtonSpec: Equatable {
        let decision: ApprovalDecisionKind
        let title: String
        let keyboardShortcut: KeyboardShortcut?
        let isEnabled: Bool

        static func makeAll(request: ApprovalRequest, scope: ApprovalScope, now: Date) -> [Self] {
            [
                Self(
                    decision: scope.decision(for: request),
                    title: scope.primaryTitle(for: request),
                    keyboardShortcut: nil,
                    isEnabled: now < request.expiresAt
                ),
                Self(decision: .deny, title: "Deny", keyboardShortcut: .cancelAction, isEnabled: true)
            ]
        }
    }
#endif
