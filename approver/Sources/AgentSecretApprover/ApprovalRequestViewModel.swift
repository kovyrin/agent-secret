import Foundation

/// Sanitized text prepared for the approval UI.
public struct ApprovalRequestViewModel: Equatable, Sendable {
    private static let secondsPerMinute: Int = 60

    /// Prompt title.
    public let title: String
    /// Request reason.
    public let reason: String
    /// Shell-rendered command display.
    public let command: String
    /// Working directory display.
    public let cwd: String
    /// Resolved executable display when known.
    public let resolvedExecutable: String?
    /// Secret alias/reference rows without secret values.
    public let secretRows: [String]
    /// Human-readable approval TTL.
    public let timeRemaining: String
    /// Reusable approval button title.
    public let allowReusableTitle: String
    /// Environment override warning when applicable.
    public let overrideWarning: String?
    /// Full sanitized prompt body for AppKit alerts.
    public let renderedText: String

    /// Builds a prompt view model without including raw secret values.
    public init(request: ApprovalRequest, now: Date = Date()) {
        title = "Approve an agent-secret request"
        reason = request.reason
        command = request.command.joined(separator: " ")
        cwd = request.cwd
        resolvedExecutable = request.resolvedExecutable
        secretRows = request.secrets.map { secret -> String in
            "\(secret.alias) -> \(secret.ref)"
        }
        timeRemaining = Self.formatRemaining(request.expiresAt.timeIntervalSince(now))
        allowReusableTitle = "Allow same command for \(timeRemaining) / \(request.reusableUses) uses"
        if request.overrideEnv, !request.overriddenAliases.isEmpty {
            overrideWarning = "Will replace existing variables: \(request.overriddenAliases.joined(separator: ", "))"
        } else {
            overrideWarning = nil
        }

        var lines: [String] = [
            title,
            "Reason: \(reason)",
            "Command: \(command)",
            "Working directory: \(cwd)"
        ]
        if let resolvedExecutable: String, !resolvedExecutable.isEmpty {
            lines.append("Resolved binary: \(resolvedExecutable)")
        }
        lines.append("Secrets:")
        lines.append(contentsOf: secretRows)
        lines.append("Time remaining: \(timeRemaining)")
        lines.append(
            "Reusable approval keeps values in daemon memory for this window " +
                "and is limited to \(request.reusableUses) uses."
        )
        if let overrideWarning: String {
            lines.append(overrideWarning)
        }
        renderedText = lines.joined(separator: "\n")
    }

    private static func formatRemaining(_ interval: TimeInterval) -> String {
        let seconds: Int = max(0, Int(interval.rounded(.down)))
        if seconds >= secondsPerMinute {
            let minutes: Int = seconds / secondsPerMinute
            let remainingSeconds: Int = seconds % secondsPerMinute
            return remainingSeconds == 0 ? "\(minutes)m" : "\(minutes)m \(remainingSeconds)s"
        }
        return "\(seconds)s"
    }
}
