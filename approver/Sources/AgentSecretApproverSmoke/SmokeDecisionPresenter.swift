import AgentSecretApprover
import Foundation

final class SmokeDecisionPresenter: ApprovalPresenter {
    private let decision: ApprovalDecisionKind

    init(decision: ApprovalDecisionKind) {
        self.decision = decision
    }

    func decide(for _: ApprovalRequest) -> ApprovalDecisionKind {
        decision
    }
}
