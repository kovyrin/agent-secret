import Foundation

/// Operation being approved by the native approver.
public enum ApprovalOperation: String, Codable, Equatable, Sendable {
    case exec
    case gcpExec = "gcp_exec"
    case gcpSessionCreate = "gcp_session_create"
    case itemDescribe = "item_describe"
    case sessionCreate = "session_create"
}
