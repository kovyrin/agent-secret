import Foundation

enum DaemonErrorDisplay {
    private enum Code {
        static let maxLength: Int = 64
    }

    private static let allowedCodeScalars = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789_")
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

    static func sanitizedCode(_ rawCode: DaemonErrorCode?) -> DaemonErrorCode {
        guard let rawCode else {
            return .unknown
        }
        if rawCode.rawValue.isEmpty || rawCode.rawValue.count > Code.maxLength {
            return .unknown
        }
        if !rawCode.rawValue.unicodeScalars.allSatisfy({ scalar in allowedCodeScalars.contains(scalar) }) {
            return .unknown
        }
        return rawCode
    }

    static func message(for rawCode: DaemonErrorCode?) -> String {
        messagesByCode[sanitizedCode(rawCode)] ?? "daemon returned an error"
    }
}
