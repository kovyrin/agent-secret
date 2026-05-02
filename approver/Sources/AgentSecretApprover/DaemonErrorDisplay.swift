import Foundation

enum DaemonErrorDisplay {
    private enum Code {
        static let unknown: String = "unknown"
        static let maxLength: Int = 64
    }

    private static let allowedCodeScalars = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789_")
    private static let messagesByCode: [String: String] = [
        "approval_denied": "approval denied",
        "approval_unavailable": "approval is unavailable",
        "approver_identity_mismatch": "approver identity did not match policy",
        "approver_peer_mismatch": "approver peer did not match request",
        "audit_failed": "required audit write failed",
        "bad_approval_decision": "daemon rejected malformed approval decision",
        "bad_command_completed": "daemon rejected malformed command completion",
        "bad_command_started": "daemon rejected malformed command start",
        "bad_envelope": "daemon rejected malformed protocol envelope",
        "bad_request": "daemon rejected malformed request",
        "bad_type": "daemon rejected unsupported message type",
        "frame_too_large": "daemon response frame was too large",
        "invalid_nonce": "request nonce did not match",
        "no_pending_approval": "no pending approval request",
        "peer_rejected": "daemon rejected peer identity",
        "request_active": "connection already has an active request",
        "request_expired": "request expired",
        "stale_approval": "stale approval response",
        "untrusted_client": "daemon rejected untrusted client"
    ]

    static func sanitizedCode(_ rawCode: String?) -> String {
        guard let rawCode else {
            return Code.unknown
        }
        if rawCode.isEmpty || rawCode.count > Code.maxLength {
            return Code.unknown
        }
        if !rawCode.unicodeScalars.allSatisfy({ scalar in allowedCodeScalars.contains(scalar) }) {
            return Code.unknown
        }
        return rawCode
    }

    static func message(for rawCode: String?) -> String {
        messagesByCode[sanitizedCode(rawCode)] ?? "daemon returned an error"
    }
}
