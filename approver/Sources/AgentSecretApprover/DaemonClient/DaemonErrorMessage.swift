import Foundation

enum DaemonErrorMessage {
    private static let messagesByCode: [DaemonErrorCode: String] = [
        .approvalDenied: "approval denied",
        .approvalUnavailable: "approval is unavailable",
        .approverIdentityMismatch: "approver identity did not match policy",
        .approverPeerMismatch: "approver peer did not match request",
        .auditFailed: "required audit write failed",
        .badApprovalDecision: "daemon rejected malformed approval decision",
        .badCommandCompleted: "daemon rejected malformed command completion",
        .badCommandStarted: "daemon rejected malformed command start",
        .badEnvelope: "daemon rejected malformed protocol envelope",
        .badRequest: "daemon rejected malformed request",
        .badType: "daemon rejected unsupported message type",
        .contextCanceled: "daemon request was canceled",
        .contextDeadlineExceeded: "daemon request deadline expired",
        .daemonStopped: "daemon stopped",
        .frameTooLarge: "daemon response frame was too large",
        .invalidNonce: "request nonce did not match",
        .noPendingApproval: "no pending approval request",
        .peerRejected: "daemon rejected peer identity",
        .requestActive: "connection already has an active request",
        .requestExpired: "request expired",
        .requestFailed: "daemon request failed",
        .resolveFailed: "daemon failed to resolve approved secret",
        .staleApproval: "stale approval response",
        .untrustedClient: "daemon rejected untrusted client"
    ]

    static func displayCode(_ code: DaemonErrorCode?) -> DaemonErrorCode {
        code ?? .unknown
    }

    static func message(for code: DaemonErrorCode?) -> String {
        messagesByCode[displayCode(code)] ?? "daemon returned an error"
    }
}
