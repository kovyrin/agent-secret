import Foundation

/// Deterministic presenter used by tests and smoke runs.
public final class StaticDecisionPresenter: ApprovalPresenter {
    private let decision: ApprovalDecisionKind

    /// Creates a presenter that always returns the supplied decision.
    public init(decision: ApprovalDecisionKind) {
        self.decision = decision
    }

    /// Returns the configured static decision.
    public func decide(for _: ApprovalRequest) -> ApprovalDecisionKind {
        decision
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
