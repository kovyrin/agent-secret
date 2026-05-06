@testable import AgentSecretApprover
import Foundation

final class FixedDecisionPresenter: ApprovalPresenter {
    private let decision: ApprovalDecisionKind
    private let denialReason: ApprovalDenialReason?

    init(decision: ApprovalDecisionKind, denialReason: ApprovalDenialReason? = nil) {
        self.decision = decision
        self.denialReason = denialReason
    }

    func decide(for _: ApprovalRequest) -> ApprovalPresentationDecision {
        ApprovalPresentationDecision(kind: decision, denialReason: denialReason)
    }
}
