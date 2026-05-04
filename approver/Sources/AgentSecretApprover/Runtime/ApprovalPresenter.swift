import Foundation

/// Main-actor decision boundary for presenters that may open native UI.
@preconcurrency
@MainActor
public protocol ApprovalPresenter {
    /// Runs on the main actor because native presenters may open AppKit UI.
    func decide(for request: ApprovalRequest) -> ApprovalDecisionKind
}
