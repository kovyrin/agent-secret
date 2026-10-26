import Foundation

/// One prompt's explicit choice and single terminal result; never persisted across requests.
struct ApprovalPanelInteraction {
    private(set) var scope: ApprovalScope = .once
    private(set) var decision: ApprovalDecisionKind?

    mutating func select(_ scope: ApprovalScope) {
        guard decision == nil else {
            return
        }
        self.scope = scope
    }

    mutating func complete(
        _ proposed: ApprovalDecisionKind,
        request: ApprovalRequest,
        at now: Date
    ) -> ApprovalDecisionKind? {
        guard decision == nil else {
            return nil
        }
        let result = ApprovalPromptExpiration(expiresAt: request.expiresAt).guardDecision(proposed, at: now)
        decision = result
        return result
    }
}
