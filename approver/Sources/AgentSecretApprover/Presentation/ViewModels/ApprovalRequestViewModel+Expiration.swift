import Foundation

extension ApprovalRequestViewModel {
    static func promptQuestion(secretCount: Int, isExpired: Bool) -> String {
        promptQuestion(operation: .exec, secretCount: secretCount, isExpired: isExpired)
    }

    static func promptQuestion(for request: ApprovalRequest, secretCount: Int, isExpired: Bool) -> String {
        promptQuestion(operation: request.operation, secretCount: secretCount, isExpired: isExpired)
    }

    static func promptQuestion(operation: ApprovalOperation, secretCount: Int, isExpired: Bool) -> String {
        if isExpired {
            switch operation {
            case .exec:
                return "This secret access request has expired."

            case .itemDescribe:
                return "This item metadata request has expired."
            }
        }
        if operation == .itemDescribe {
            return "Allow this command to inspect this 1Password item?"
        }
        if secretCount == 1 {
            return "Allow this command to use the following secret?"
        }
        return "Allow this command to use the following \(secretCount) secrets?"
    }

    static func accessSummary(isExpired: Bool) -> String {
        accessSummary(operation: .exec, isExpired: isExpired)
    }

    static func accessSummary(operation: ApprovalOperation, isExpired: Bool) -> String {
        if isExpired {
            return "can no longer receive access."
        }
        if operation == .itemDescribe {
            return "wants item metadata access."
        }
        return "wants temporary access."
    }

    static func footerMessage(secretCount: Int, expired: Bool) -> String {
        footerMessage(operation: .exec, secretCount: secretCount, expired: expired)
    }

    static func footerMessage(for request: ApprovalRequest, secretCount: Int, expired: Bool) -> String {
        footerMessage(operation: request.operation, secretCount: secretCount, expired: expired)
    }

    static func footerMessage(operation: ApprovalOperation, secretCount: Int, expired: Bool) -> String {
        if expired {
            return "This request expired before approval. Run the command again if access is still needed."
        }
        if operation == .itemDescribe {
            return """
            Only item metadata is returned.
            Secret values are never shown to the agent or stored on disk.
            """
        }
        let noun: String = secretCount == 1 ? "secret is" : "secrets are"
        let pronoun: String = secretCount == 1 ? "It is" : "They are"
        return """
        The \(noun) injected into the approved process only.
        \(pronoun) never shown to the agent or stored on disk.
        """
    }

    static func scopeSummary(uses: Int, remaining: String, expired: Bool) -> String {
        scopeSummary(uses: uses, remaining: remaining, expired: expired, allowsReusable: true)
    }

    static func scopeSummary(for request: ApprovalRequest, remaining: String, expired: Bool) -> String {
        scopeSummary(
            uses: request.reusableUses,
            remaining: remaining,
            expired: expired,
            allowsReusable: request.allowsReusable
        )
    }

    static func scopeSummary(uses: Int, remaining: String, expired: Bool, allowsReusable: Bool) -> String {
        if !allowsReusable {
            if expired {
                return "One metadata lookup only\nrequest expired"
            }
            return "One metadata lookup only\nexpires in \(remaining)"
        }
        if expired {
            return "Same command only • max \(uses) uses\nrequest expired"
        }
        return "Same command only • max \(uses) uses\nexpires in \(remaining)"
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
