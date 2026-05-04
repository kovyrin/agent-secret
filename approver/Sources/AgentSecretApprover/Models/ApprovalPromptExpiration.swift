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
        switch decision {
        case .approveOnce, .approveReusable:
            isExpired(at: now) ? .timeout : decision

        default:
            decision
        }
    }
}
