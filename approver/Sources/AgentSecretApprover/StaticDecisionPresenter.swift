import Foundation

/// Deterministic presenter used by tests and smoke runs.
public final class StaticDecisionPresenter: ApprovalPresenter {
    private let decision: ApprovalDecisionKind

    public init(decision: ApprovalDecisionKind) {
        self.decision = decision
    }

    public func decide(for _: ApprovalRequest) -> ApprovalDecisionKind {
        decision
    }
}
