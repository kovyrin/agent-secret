import Foundation

public final class StaticDecisionPresenter: ApprovalPresenter {
    private let decision: ApprovalDecisionKind

    public init(decision: ApprovalDecisionKind) {
        self.decision = decision
    }

    public func decide(for _: ApprovalRequest) -> ApprovalDecisionKind {
        decision
    }
}
