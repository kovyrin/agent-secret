import Foundation

/// Daemon connection used by the approver to fetch requests and submit decisions.
public protocol ApprovalDaemonClient {
    /// Returns the pending approval request for this approver invocation.
    func fetchPendingRequest() throws -> ApprovalRequest

    /// Submits the operator decision back to the daemon.
    func submit(_ decision: ApprovalDecision) throws
}
