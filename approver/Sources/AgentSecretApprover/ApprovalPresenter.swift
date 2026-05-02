import Foundation

/// Presents an approval request and returns the operator decision.
@preconcurrency
@MainActor
public protocol ApprovalPresenter {
    /// Returns the decision selected for a request.
    func decide(for request: ApprovalRequest) -> ApprovalDecisionKind
}
