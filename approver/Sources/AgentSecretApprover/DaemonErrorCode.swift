import Foundation

enum DaemonErrorCode: String, Codable, Equatable, Hashable {
    case approvalDenied = "approval_denied"
    case approvalUnavailable = "approval_unavailable"
    case approverIdentityMismatch = "approver_identity_mismatch"
    case approverPeerMismatch = "approver_peer_mismatch"
    case auditFailed = "audit_failed"
    case badApprovalDecision = "bad_approval_decision"
    case badCommandCompleted = "bad_command_completed"
    case badCommandStarted = "bad_command_started"
    case badEnvelope = "bad_envelope"
    case badRequest = "bad_request"
    case badType = "bad_type"
    case contextCanceled = "context_canceled"
    case contextDeadlineExceeded = "context_deadline_exceeded"
    case daemonStopped = "daemon_stopped"
    case frameTooLarge = "frame_too_large"
    case invalidNonce = "invalid_nonce"
    case noPendingApproval = "no_pending_approval"
    case peerRejected = "peer_rejected"
    case requestActive = "request_active"
    case requestExpired = "request_expired"
    case requestFailed = "request_failed"
    case resolveFailed = "resolve_failed"
    case staleApproval = "stale_approval"
    case unknown
    case untrustedClient = "untrusted_client"

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let rawValue = try container.decode(String.self)
        self = Self(rawValue: rawValue) ?? .unknown
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}
