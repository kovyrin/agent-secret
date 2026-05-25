import Foundation

extension ApprovalRequestViewModel {
    struct CopyPresentation {
        let isExpired: Bool
        let timeRemaining: String
        let promptQuestion: String
        let accessSummary: String
        let scopeSummary: String
        let allowReusableTitle: String
        let footerMessage: String
    }

    static func copyPresentation(for request: ApprovalRequest, count: Int, now: Date) -> CopyPresentation {
        let remaining: TimeInterval = request.expiresAt.timeIntervalSince(now)
        let expired: Bool = Self.isExpired(remaining)
        let remainingText: String = expired ? Self.expiredTimeRemaining() : Self.formatRemaining(remaining)
        return CopyPresentation(
            isExpired: expired,
            timeRemaining: remainingText,
            promptQuestion: Self.promptQuestion(operation: request.operation, resourceCount: count, isExpired: expired),
            accessSummary: Self.accessSummary(operation: request.operation, isExpired: expired),
            scopeSummary: Self.scopeSummary(
                operation: request.operation,
                uses: request.reusableUses,
                remaining: remainingText,
                expired: expired,
                allowsReusable: request.allowsReusable
            ),
            allowReusableTitle: Self.reuseTitle(uses: request.reusableUses, remaining: remainingText, expired: expired),
            footerMessage: Self.footerMessage(operation: request.operation, resourceCount: count, expired: expired)
        )
    }

    static func promptQuestion(operation: ApprovalOperation, resourceCount: Int, isExpired: Bool) -> String {
        if isExpired {
            switch operation {
            case .exec:
                return "This secret access request has expired."

            case .itemDescribe:
                return "This item metadata request has expired."

            case .gcpExec, .gcpSessionCreate:
                return "This GCP access request has expired."
            }
        }
        if operation == .itemDescribe {
            return "Allow this command to inspect this 1Password item?"
        }
        if operation == .gcpExec {
            return "Allow this command to use this GCP capability?"
        }
        if operation == .gcpSessionCreate {
            return "Allow this GCP session?"
        }
        if resourceCount == 1 {
            return "Allow this command to use the following secret?"
        }
        return "Allow this command to use the following \(resourceCount) secrets?"
    }

    static func accessSummary(operation: ApprovalOperation, isExpired: Bool) -> String {
        if isExpired {
            return "can no longer receive access."
        }
        if operation == .itemDescribe {
            return "wants item metadata access."
        }
        if operation == .gcpExec || operation == .gcpSessionCreate {
            return "wants temporary GCP access."
        }
        return "wants temporary access."
    }

    static func footerMessage(operation: ApprovalOperation, resourceCount: Int, expired: Bool) -> String {
        if expired {
            return "This request expired before approval. Run the command again if access is still needed."
        }
        if operation == .itemDescribe {
            return """
            Only item metadata is returned.
            Secret values are never shown to the agent or stored on disk.
            """
        }
        if operation == .gcpExec || operation == .gcpSessionCreate {
            return """
            Agent Secret prepares isolated Cloud SDK state for approved commands.
            Access tokens are not shown to the agent.
            """
        }
        let noun: String = resourceCount == 1 ? "secret is" : "secrets are"
        let pronoun: String = resourceCount == 1 ? "It is" : "They are"
        return """
        The \(noun) injected into the approved process only.
        \(pronoun) never shown to the agent or stored on disk.
        """
    }

    static func scopeSummary(
        operation: ApprovalOperation,
        uses: Int,
        remaining: String,
        expired: Bool,
        allowsReusable: Bool
    ) -> String {
        if operation == .gcpSessionCreate {
            if expired {
                return "GCP session • max \(uses) command starts\nrequest expired"
            }
            return "GCP session • max \(uses) command starts\nexpires in \(remaining)"
        }
        if operation == .gcpExec {
            if expired {
                return "One GCP command only\nrequest expired"
            }
            return "One GCP command only\nexpires in \(remaining)"
        }
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
