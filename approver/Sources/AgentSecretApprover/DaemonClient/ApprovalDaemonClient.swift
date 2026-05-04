import Foundation

/// Value-free daemon boundary for the native approver; only request metadata and decisions cross it.
public protocol ApprovalDaemonClient {
    /// Reads pending request metadata without transferring secret values into the UI process.
    func fetchPendingRequest() throws -> ApprovalRequest

    /// Sends a decision that preserves the fetched request's daemon nonce and request ID.
    func submit(_ decision: ApprovalDecision) throws
}
