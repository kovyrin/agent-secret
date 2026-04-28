import Foundation

/// Operator decision returned by the native approver.
public enum ApprovalDecisionKind: String, Codable, Equatable, Sendable {
    /// Approve exactly one command launch.
    case approveOnce = "approve_once"
    /// Approve the same command for the bounded reusable window.
    case approveReusable = "approve_reusable"
    /// Reject the request.
    case deny = "deny"
    /// Treat the request as unanswered.
    case timeout = "timeout"
}
