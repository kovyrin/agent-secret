import Foundation

struct ApprovalPromptExpiration: Equatable {
    let expiresAt: Date

    func isExpired(at now: Date) -> Bool {
        now >= expiresAt
    }

    func timeoutDecision(at now: Date) -> ApprovalDecisionKind? {
        isExpired(at: now) ? .timeout : nil
    }

    func guardDecision(_ decision: ApprovalDecisionKind, at now: Date) -> ApprovalDecisionKind {
        if decision.requiresUnexpiredRequest, isExpired(at: now) {
            return .timeout
        }
        return decision
    }
}
