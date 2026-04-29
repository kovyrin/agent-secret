import Foundation

/// Sanitized text prepared for the approval UI.
public struct ApprovalRequestViewModel: Equatable, Sendable {
    private struct SecretPresentation {
        let rows: [RequestedSecretRowViewModel]
        let rowText: [String]
        let count: Int
        let vaultGroups: [SecretVaultGroupViewModel]
        let vaultCount: Int
    }

    private struct SelfRenderInput {
        let title: String
        let reason: String
        let command: String
        let cwd: String
        let scopeSummary: String
        let resolvedExecutable: String?
        let secretRows: [String]
        let timeRemaining: String
        let overrideWarning: String?
    }

    private static let highScopeSecretThreshold: Int = 6
    private static let secondsPerMinute: Int = 60

    /// Prompt title.
    public let title: String
    /// Request reason.
    public let reason: String
    /// Shell-rendered command display.
    public let command: String
    /// Executable path displayed in the approval summary.
    public let executable: String
    /// Working directory display.
    public let cwd: String
    /// Working directory display shortened for the current user.
    public let projectFolder: String
    /// Resolved executable display when known.
    public let resolvedExecutable: String?
    /// Secret alias/ref rows without secret values.
    public let requestedSecrets: [RequestedSecretRowViewModel]
    /// Secret alias/reference rows without secret values.
    public let secretRows: [String]
    /// Total number of requested secrets.
    public let secretCount: Int
    /// Requested secrets grouped by vault.
    public let vaultGroups: [SecretVaultGroupViewModel]
    /// Number of vaults represented by this request.
    public let vaultCount: Int
    /// Main prompt question.
    public let promptQuestion: String
    /// Summary text next to the command pill.
    public let accessSummary: String
    /// True when the number of requested secrets deserves extra attention.
    public let highScopeWarning: Bool
    /// Human-readable approval TTL.
    public let timeRemaining: String
    /// Compact timer string for approval buttons.
    public let compactTimeRemaining: String
    /// Maximum launches covered by reusable approval.
    public let reusableUses: Int
    /// Reusable approval scope summary.
    public let scopeSummary: String
    /// Reusable approval button title.
    public let allowReusableTitle: String
    /// True when the command commonly prints its environment.
    public let printsEnvironmentWarning: Bool
    /// Environment override warning when applicable.
    public let overrideWarning: String?
    /// Footer copy with correct singular/plural wording.
    public let footerMessage: String
    /// Full sanitized prompt body for AppKit alerts.
    public let renderedText: String

    /// Builds a prompt view model without including raw secret values.
    public init(request: ApprovalRequest, now: Date = Date()) {
        title = "Secret Access Request"
        reason = request.reason
        executable = request.resolvedExecutable ?? request.command.first ?? "unknown command"
        command = Self.commandDisplay(request.command, resolvedExecutable: request.resolvedExecutable)
        cwd = request.cwd
        projectFolder = Self.displayPath(request.cwd)
        resolvedExecutable = request.resolvedExecutable
        let secretPresentation: SecretPresentation = Self.secretPresentation(for: request.secrets)
        requestedSecrets = secretPresentation.rows
        secretRows = secretPresentation.rowText
        secretCount = secretPresentation.count
        vaultGroups = secretPresentation.vaultGroups
        vaultCount = secretPresentation.vaultCount
        promptQuestion = Self.promptQuestion(secretCount: secretPresentation.count)
        accessSummary = Self.accessSummary(
            secretCount: secretPresentation.count,
            vaultCount: secretPresentation.vaultCount
        )
        highScopeWarning = secretPresentation.count >= Self.highScopeSecretThreshold
        let remaining: TimeInterval = request.expiresAt.timeIntervalSince(now)
        timeRemaining = Self.formatRemaining(remaining)
        compactTimeRemaining = Self.formatCompactRemaining(remaining)
        reusableUses = request.reusableUses
        scopeSummary = Self.scopeSummary(
            reusableUses: request.reusableUses,
            compactTimeRemaining: compactTimeRemaining
        )
        allowReusableTitle = "Allow same command briefly\n\(compactTimeRemaining) or \(request.reusableUses) uses"
        printsEnvironmentWarning = Self.environmentPrinter(
            command: request.command,
            resolvedExecutable: request.resolvedExecutable
        )
        overrideWarning = Self.overrideWarning(for: request)
        footerMessage = Self.footerMessage(secretCount: secretPresentation.count)
        renderedText = Self.renderedText(
            for: request,
            viewModel: SelfRenderInput(
                title: title,
                reason: reason,
                command: command,
                cwd: cwd,
                scopeSummary: scopeSummary,
                resolvedExecutable: resolvedExecutable,
                secretRows: secretRows,
                timeRemaining: timeRemaining,
                overrideWarning: overrideWarning
            )
        )
    }

    private static func secretPresentation(for secrets: [RequestedSecret]) -> SecretPresentation {
        let rows: [RequestedSecretRowViewModel] = secrets.map { secret -> RequestedSecretRowViewModel in
            RequestedSecretRowViewModel(alias: secret.alias, ref: secret.ref)
        }
        let rowText: [String] = rows.map { secret -> String in
            "\(secret.alias) -> \(secret.ref)"
        }
        let vaultGroups: [SecretVaultGroupViewModel] = Self.vaultGroups(for: rows)
        return SecretPresentation(
            rows: rows,
            rowText: rowText,
            count: rows.count,
            vaultGroups: vaultGroups,
            vaultCount: vaultGroups.count
        )
    }

    private static func vaultGroups(for rows: [RequestedSecretRowViewModel]) -> [SecretVaultGroupViewModel] {
        var groups: [SecretVaultGroupViewModel] = []
        var groupIndexesByVault: [String: Int] = [:]
        for row in rows {
            if let index: Int = groupIndexesByVault[row.vaultName] {
                var group: SecretVaultGroupViewModel = groups[index]
                group = SecretVaultGroupViewModel(vaultName: group.vaultName, secrets: group.secrets + [row])
                groups[index] = group
            } else {
                groupIndexesByVault[row.vaultName] = groups.count
                groups.append(SecretVaultGroupViewModel(vaultName: row.vaultName, secrets: [row]))
            }
        }
        return groups
    }

    private static func promptQuestion(secretCount: Int) -> String {
        if secretCount == 1 {
            return "Allow this command to use a secret?"
        }
        return "Allow this command to use \(secretCount) secrets?"
    }

    private static func accessSummary(secretCount: Int, vaultCount: Int) -> String {
        if secretCount == 1 {
            return "wants temporary access to"
        }
        if vaultCount > 1 {
            return "wants temporary access to \(secretCount) secrets from \(vaultCount) vaults."
        }
        return "wants temporary access to \(secretCount) secrets."
    }

    private static func footerMessage(secretCount: Int) -> String {
        let noun: String = secretCount == 1 ? "secret is" : "secrets are"
        let pronoun: String = secretCount == 1 ? "It is" : "They are"
        return """
        The \(noun) injected into the approved process only.
        \(pronoun) never shown to the agent or stored on disk.
        """
    }

    private static func renderedText(
        for request: ApprovalRequest,
        viewModel: SelfRenderInput
    ) -> String {
        var lines: [String] = [
            viewModel.title,
            "Reason: \(viewModel.reason)",
            "Command: \(viewModel.command)",
            "Working directory: \(viewModel.cwd)",
            "Scope: \(viewModel.scopeSummary)"
        ]
        if let resolvedExecutable: String = viewModel.resolvedExecutable, !resolvedExecutable.isEmpty {
            lines.append("Resolved binary: \(resolvedExecutable)")
        }
        lines.append("Secrets:")
        lines.append(contentsOf: viewModel.secretRows)
        lines.append("Time remaining: \(viewModel.timeRemaining)")
        lines.append(
            "Reusable approval keeps values in daemon memory for this window " +
                "and is limited to \(request.reusableUses) uses."
        )
        if let overrideWarning: String = viewModel.overrideWarning {
            lines.append(overrideWarning)
        }
        return lines.joined(separator: "\n")
    }

    private static func overrideWarning(for request: ApprovalRequest) -> String? {
        guard request.overrideEnv, !request.overriddenAliases.isEmpty else {
            return nil
        }
        return "Will replace existing variables: \(request.overriddenAliases.joined(separator: ", "))"
    }

    private static func commandDisplay(_ command: [String], resolvedExecutable: String?) -> String {
        guard !command.isEmpty else {
            return "unknown command"
        }
        guard let resolvedExecutable: String, !resolvedExecutable.isEmpty else {
            return command.joined(separator: " ")
        }
        var parts: [String] = command
        parts[0] = resolvedExecutable
        return parts.joined(separator: " ")
    }

    private static func scopeSummary(reusableUses: Int, compactTimeRemaining: String) -> String {
        "Same command only • max \(reusableUses) uses • expires in \(compactTimeRemaining)"
    }

    private static func displayPath(_ path: String) -> String {
        guard let home: String = ProcessInfo.processInfo.environment["HOME"], !home.isEmpty else {
            return path
        }
        if path == home {
            return "~"
        }
        if path.hasPrefix(home + "/") {
            return "~" + path.dropFirst(home.count)
        }
        return path
    }

    private static func formatRemaining(_ interval: TimeInterval) -> String {
        let seconds: Int = Self.visibleRemainingSeconds(interval)
        if seconds >= secondsPerMinute {
            let minutes: Int = seconds / secondsPerMinute
            let remainingSeconds: Int = seconds % secondsPerMinute
            return remainingSeconds == 0 ? "\(minutes)m" : "\(minutes)m \(remainingSeconds)s"
        }
        return "\(seconds)s"
    }

    private static func formatCompactRemaining(_ interval: TimeInterval) -> String {
        let seconds: Int = Self.visibleRemainingSeconds(interval)
        let minutes: Int = seconds / secondsPerMinute
        let remainingSeconds: Int = seconds % secondsPerMinute
        return String(format: "%d:%02d", minutes, remainingSeconds)
    }

    private static func visibleRemainingSeconds(_ interval: TimeInterval) -> Int {
        max(0, Int(interval.rounded(.up)))
    }

    private static func environmentPrinter(command: [String], resolvedExecutable: String?) -> Bool {
        let executableName: String = URL(fileURLWithPath: resolvedExecutable ?? command.first ?? "")
            .lastPathComponent
        return executableName == "env" || executableName == "printenv"
    }
}
