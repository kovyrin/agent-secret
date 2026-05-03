import Foundation

/// Presents an approval request and returns the operator decision.
@preconcurrency
@MainActor
public protocol ApprovalPresenter {
    /// Runs on the main actor because native presenters may open AppKit UI.
    func decide(for request: ApprovalRequest) -> ApprovalDecisionKind
}
