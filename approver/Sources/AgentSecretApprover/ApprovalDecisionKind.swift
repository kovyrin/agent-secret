import Foundation

/// Operator decision returned by the native approver.
public enum ApprovalDecisionKind: String, Codable, Equatable, Sendable {
    case approveOnce = "approve_once"
    case approveReusable = "approve_reusable"
    case deny
    case timeout

    var requiresUnexpiredRequest: Bool {
        self == .approveOnce || self == .approveReusable
    }
}
