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
        let commandArgumentRows: [String]
        let cwd: String
        let scopeSummary: String
        let resolvedExecutable: String?
        let secretRows: [String]
        let timeRemaining: String
        let overrideWarning: String?
        let mutableExecutableWarning: String?
    }

    private static let highScopeSecretThreshold: Int = 6
    private static let commandInspectorThreshold: Int = 96
    private static let secondsPerMinute: Int = 60

    /// Prompt title.
    public let title: String
    /// Request reason.
    public let reason: String
    /// Shell-escaped compact argv display.
    public let command: String
    /// True when the command should expose a full-text inspector affordance.
    public let commandNeedsInspector: Bool
    /// Structured argv rows for the full command inspector.
    public let commandInspectionText: String
    /// One view model per argv element.
    let commandArguments: [CommandArgumentViewModel]
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
    /// True when the request can no longer be approved.
    public let isExpired: Bool
    /// True when the number of requested secrets deserves extra attention.
    public let highScopeWarning: Bool
    /// Human-readable approval TTL.
    public let timeRemaining: String
    /// Human-readable timer string for approval buttons.
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
    /// Mutable executable opt-in warning when applicable.
    public let mutableExecutableWarning: String?
    /// Footer copy with correct singular/plural wording.
    public let footerMessage: String
    /// Full sanitized prompt body for AppKit alerts.
    public let renderedText: String

    /// Builds a prompt view model without including raw secret values.
    public init(request: ApprovalRequest, now: Date = Date()) {
        title = "Secret Access Request"
        reason = request.reason
        executable = Self.executableName(request.resolvedExecutable ?? request.command.first)
        commandArguments = Self.commandArguments(request.command)
        command = Self.commandDisplay(commandArguments)
        commandNeedsInspector = Self.commandNeedsInspector(command, arguments: commandArguments)
        commandInspectionText = Self.commandInspectionText(commandArguments)
        cwd = request.cwd
        projectFolder = Self.displayPath(request.cwd)
        resolvedExecutable = request.resolvedExecutable
        let secretPresentation: SecretPresentation = Self.secretPresentation(for: request.secrets)
        requestedSecrets = secretPresentation.rows
        secretRows = secretPresentation.rowText
        secretCount = secretPresentation.count
        vaultGroups = secretPresentation.vaultGroups
        vaultCount = secretPresentation.vaultCount
        let remaining: TimeInterval = request.expiresAt.timeIntervalSince(now)
        isExpired = Self.isExpired(remaining)
        promptQuestion = Self.promptQuestion(secretCount: secretPresentation.count, isExpired: isExpired)
        accessSummary = Self.accessSummary(isExpired: isExpired)
        highScopeWarning = secretPresentation.count >= Self.highScopeSecretThreshold
        timeRemaining = isExpired ? Self.expiredTimeRemaining() : Self.formatRemaining(remaining)
        compactTimeRemaining = timeRemaining
        let reusableUseLimit: Int = request.reusableUses
        reusableUses = reusableUseLimit
        let remainingText: String = compactTimeRemaining
        scopeSummary = Self.scopeSummary(uses: reusableUseLimit, remaining: remainingText, expired: isExpired)
        allowReusableTitle = Self.reuseTitle(uses: reusableUseLimit, remaining: remainingText, expired: isExpired)
        printsEnvironmentWarning = Self.environmentWarning(for: request)
        overrideWarning = Self.overrideWarning(for: request)
        mutableExecutableWarning = Self.mutableExecutableWarning(for: request)
        footerMessage = Self.footerMessage(secretCount: secretPresentation.count, expired: isExpired)
        renderedText = Self.renderedText(
            for: request,
            viewModel: SelfRenderInput(
                title: title,
                reason: reason,
                command: command,
                commandArgumentRows: commandArguments.map(\.inspectorLine),
                cwd: cwd,
                scopeSummary: scopeSummary,
                resolvedExecutable: resolvedExecutable,
                secretRows: secretRows,
                timeRemaining: timeRemaining,
                overrideWarning: overrideWarning,
                mutableExecutableWarning: mutableExecutableWarning
            )
        )
    }

    private static func secretPresentation(for secrets: [RequestedSecret]) -> SecretPresentation {
        let rows: [RequestedSecretRowViewModel] = secrets.map { secret -> RequestedSecretRowViewModel in
            RequestedSecretRowViewModel(alias: secret.alias, ref: secret.ref, account: secret.account)
        }
        let rowText: [String] = rows.map { secret -> String in
            Self.secretRowText(secret)
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
        var groupIndexesByScope: [String: Int] = [:]
        for row in rows {
            if let index: Int = groupIndexesByScope[row.vaultScopeName] {
                var group: SecretVaultGroupViewModel = groups[index]
                group = SecretVaultGroupViewModel(vaultName: group.vaultName, secrets: group.secrets + [row])
                groups[index] = group
            } else {
                groupIndexesByScope[row.vaultScopeName] = groups.count
                groups.append(SecretVaultGroupViewModel(vaultName: row.vaultScopeName, secrets: [row]))
            }
        }
        return groups
    }

    private static func secretRowText(_ secret: RequestedSecretRowViewModel) -> String {
        if let accountLabel: String = secret.accountLabel {
            return "\(secret.alias) [\(accountLabel)] -> \(secret.ref)"
        }
        return "\(secret.alias) -> \(secret.ref)"
    }

    private static func renderedText(
        for request: ApprovalRequest,
        viewModel: SelfRenderInput
    ) -> String {
        var lines: [String] = [
            viewModel.title,
            "Reason: \(viewModel.reason)",
            "Command: \(viewModel.command)",
            "Command argv:"
        ]
        lines.append(contentsOf: viewModel.commandArgumentRows)
        lines.append(contentsOf: [
            "Working directory: \(viewModel.cwd)",
            "Scope: \(viewModel.scopeSummary)"
        ])
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
        if let mutableExecutableWarning: String = viewModel.mutableExecutableWarning {
            lines.append(mutableExecutableWarning)
        }
        return lines.joined(separator: "\n")
    }

    private static func overrideWarning(for request: ApprovalRequest) -> String? {
        guard request.overrideEnv, !request.overriddenAliases.isEmpty else {
            return nil
        }
        return "Will replace existing variables: \(request.overriddenAliases.joined(separator: ", "))"
    }

    private static func mutableExecutableWarning(for request: ApprovalRequest) -> String? {
        guard request.allowMutableExecutable else {
            return nil
        }
        return "Mutable executable opt-in: command path may be replaceable before launch."
    }

    private static func commandArguments(_ command: [String]) -> [CommandArgumentViewModel] {
        command.enumerated().map { index, value in
            CommandArgumentViewModel(index: index, value: value)
        }
    }

    private static func commandDisplay(_ arguments: [CommandArgumentViewModel]) -> String {
        guard !arguments.isEmpty else {
            return "unknown command"
        }
        return arguments.map(\.escaped).joined(separator: " ")
    }

    private static func commandInspectionText(_ arguments: [CommandArgumentViewModel]) -> String {
        arguments.map(\.inspectorLine).joined(separator: "\n")
    }

    private static func commandNeedsInspector(_ command: String, arguments: [CommandArgumentViewModel]) -> Bool {
        command.count > commandInspectorThreshold || arguments.contains(where: \.needsInspector)
    }

    private static func executableName(_ path: String?) -> String {
        guard let path, !path.isEmpty else {
            return "unknown command"
        }
        return URL(fileURLWithPath: path).lastPathComponent
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

    private static func environmentPrinter(command: [String], resolvedExecutable: String?) -> Bool {
        let executableName: String = URL(fileURLWithPath: resolvedExecutable ?? command.first ?? "")
            .lastPathComponent
        return executableName == "env" || executableName == "printenv"
    }

    private static func environmentWarning(for request: ApprovalRequest) -> Bool {
        environmentPrinter(command: request.command, resolvedExecutable: request.resolvedExecutable)
    }
}
