import Foundation

extension ApprovalRequestViewModel {
    static func promptQuestion(secretCount: Int, isExpired: Bool) -> String {
        if isExpired {
            return "This secret access request has expired."
        }
        if secretCount == 1 {
            return "Allow this command to use the following secret?"
        }
        return "Allow this command to use the following \(secretCount) secrets?"
    }

    static func accessSummary(isExpired: Bool) -> String {
        if isExpired {
            return "can no longer receive access."
        }
        return "wants temporary access."
    }

    static func footerMessage(secretCount: Int, expired: Bool) -> String {
        if expired {
            return "This request expired before approval. Run the command again if access is still needed."
        }
        let noun: String = secretCount == 1 ? "secret is" : "secrets are"
        let pronoun: String = secretCount == 1 ? "It is" : "They are"
        return """
        The \(noun) injected into the approved process only.
        \(pronoun) never shown to the agent or stored on disk.
        """
    }

    static func scopeSummary(uses: Int, remaining: String, expired: Bool) -> String {
        if expired {
            return "Same command only • max \(uses) uses • request expired"
        }
        return "Same command only • max \(uses) uses • expires in \(remaining)"
    }

    static func reuseTitle(uses: Int, remaining: String, expired: Bool) -> String {
        if expired {
            return "Allow same command briefly\nRequest expired"
        }
        return "Allow same command briefly\n\(remaining) or \(uses) uses"
    }

    static func isExpired(_ interval: TimeInterval) -> Bool {
        interval <= 0
    }

    static func expiredTimeRemaining() -> String {
        "expired"
    }
}
