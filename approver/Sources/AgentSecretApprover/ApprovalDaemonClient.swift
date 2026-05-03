import Foundation

/// Daemon connection used by the approver to fetch requests and submit decisions.
public protocol ApprovalDaemonClient {
    /// Opens the approval-pending protocol request without exposing secret values.
    func fetchPendingRequest() throws -> ApprovalRequest

    /// Sends a decision that preserves the fetched request's daemon nonce and request ID.
    func submit(_ decision: ApprovalDecision) throws
}
