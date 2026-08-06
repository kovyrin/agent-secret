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

    private static let secondsPerMinute = 60

    static func copyPresentation(
        for request: ApprovalRequest,
        count: Int,
        requester: String?,
        now: Date
    ) -> CopyPresentation {
        let remaining: TimeInterval = request.expiresAt.timeIntervalSince(now)
        let expired: Bool = Self.isExpired(remaining)
        let remainingText: String = expired ? Self.expiredTimeRemaining() : Self.formatRemaining(remaining)
        let accessDuration: String? = request.accessDurationSeconds.map { seconds in
            Self.formatRemaining(TimeInterval(seconds))
        }
        return CopyPresentation(
            isExpired: expired,
            timeRemaining: remainingText,
            promptQuestion: Self.promptQuestion(
                operation: request.operation,
                resourceCount: count,
                isExpired: expired,
                requester: requester
            ),
            accessSummary: Self.accessSummary(operation: request.operation, isExpired: expired),
            scopeSummary: Self.scopeSummary(
                request: request,
                remaining: remainingText,
                accessDuration: accessDuration,
                expired: expired
            ),
            allowReusableTitle: Self.reuseTitle(uses: request.reusableUses, remaining: remainingText, expired: expired),
            footerMessage: Self.footerMessage(operation: request.operation, resourceCount: count, expired: expired)
        )
    }

    static func promptQuestion(
        operation: ApprovalOperation,
        resourceCount: Int,
        isExpired: Bool,
        requester: String?
    ) -> String {
        if isExpired {
            switch operation {
            case .exec:
                return "This secret access request has expired."

            case .itemDescribe:
                return "This item metadata request has expired."

            case .sessionCreate:
                return "This session access request has expired."
            }
        }
        if operation == .itemDescribe {
            return "Allow this command to inspect this 1Password item?"
        }
        if operation == .sessionCreate {
            let subject: String = requester ?? "this session"
            return resourceCount == 1 ?
                "Allow \(subject) to use the following secret?" :
                "Allow \(subject) to use the following \(resourceCount) secrets?"
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
        if operation == .sessionCreate {
            return "wants short session access."
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
        if operation == .sessionCreate {
            return """
            The session keeps approved values in daemon memory only.
            Values are injected only by with-session and are never printed.
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
        request: ApprovalRequest,
        remaining: String,
        accessDuration: String?,
        expired: Bool
    ) -> String {
        if request.operation == .sessionCreate {
            if expired {
                return "One approved session\nrequest expired"
            }
            guard let accessDuration else {
                return "One approved session\nAccess starts after approval"
            }
            return "One approved session\nAccess for \(accessDuration) after approval"
        }
        if !request.allowsReusable {
            if expired {
                return "One approved operation only\nrequest expired"
            }
            return "One approved operation only\nexpires in \(remaining)"
        }
        if expired {
            return "Same command only • max \(request.reusableUses) uses\nrequest expired"
        }
        return "Same command only • max \(request.reusableUses) uses\nexpires in \(remaining)"
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

    static func formatRemaining(_ interval: TimeInterval) -> String {
        let seconds: Int = Self.visibleRemainingSeconds(interval)
        if seconds >= secondsPerMinute {
            let minutes: Int = seconds / secondsPerMinute
            let remainingSeconds: Int = seconds % secondsPerMinute
            if remainingSeconds == 0 {
                return minutes == 1 ? "1 minute" : "\(minutes) minutes"
            }
            return "\(minutes) min \(remainingSeconds) sec"
        }
        return seconds == 1 ? "1 second" : "\(seconds) sec"
    }

    private static func visibleRemainingSeconds(_ interval: TimeInterval) -> Int {
        max(0, Int(interval.rounded(.up)))
    }
}
