import Foundation

/// Wire values accepted by the daemon approval protocol; approve cases require an unexpired request.
public enum ApprovalDecisionKind: String, Codable, Equatable, Sendable {
    case approveOnce = "approve_once"
    case approveReusable = "approve_reusable"
    case deny
    case timeout

    var requiresUnexpiredRequest: Bool {
        self == .approveOnce || self == .approveReusable
    }
}
