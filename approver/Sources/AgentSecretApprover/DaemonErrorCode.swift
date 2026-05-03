import Foundation

struct DaemonErrorCode: Codable, Equatable, ExpressibleByStringLiteral, Hashable, RawRepresentable {
    static let unknown = Self(rawValue: "unknown")
    static let approvalDenied = Self(rawValue: "approval_denied")
    static let approvalUnavailable = Self(rawValue: "approval_unavailable")
    static let approverIdentityMismatch = Self(rawValue: "approver_identity_mismatch")
    static let approverPeerMismatch = Self(rawValue: "approver_peer_mismatch")
    static let auditFailed = Self(rawValue: "audit_failed")
    static let badApprovalDecision = Self(rawValue: "bad_approval_decision")
    static let badCommandCompleted = Self(rawValue: "bad_command_completed")
    static let badCommandStarted = Self(rawValue: "bad_command_started")
    static let badEnvelope = Self(rawValue: "bad_envelope")
    static let badRequest = Self(rawValue: "bad_request")
    static let badType = Self(rawValue: "bad_type")
    static let contextCanceled = Self(rawValue: "context_canceled")
    static let contextDeadlineExceeded = Self(rawValue: "context_deadline_exceeded")
    static let daemonStopped = Self(rawValue: "daemon_stopped")
    static let frameTooLarge = Self(rawValue: "frame_too_large")
    static let invalidNonce = Self(rawValue: "invalid_nonce")
    static let noPendingApproval = Self(rawValue: "no_pending_approval")
    static let peerRejected = Self(rawValue: "peer_rejected")
    static let requestActive = Self(rawValue: "request_active")
    static let requestExpired = Self(rawValue: "request_expired")
    static let requestFailed = Self(rawValue: "request_failed")
    static let resolveFailed = Self(rawValue: "resolve_failed")
    static let staleApproval = Self(rawValue: "stale_approval")
    static let untrustedClient = Self(rawValue: "untrusted_client")

    let rawValue: String

    init(rawValue: String) {
        self.rawValue = rawValue
    }

    init(stringLiteral value: String) {
        self.init(rawValue: value)
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        rawValue = try container.decode(String.self)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}
