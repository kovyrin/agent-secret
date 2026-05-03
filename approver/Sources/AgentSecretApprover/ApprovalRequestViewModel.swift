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
        let cautionMessages: [String]
    }

    private static let highScopeSecretThreshold: Int = 6
    private static let commandInspectorThreshold: Int = 96
    private static let secondsPerMinute: Int = 60

    public let title: String
    public let reason: String
    public let command: String
    public let commandNeedsInspector: Bool
    public let commandInspectionText: String
    let commandArguments: [CommandArgumentViewModel]
    public let executable: String
    public let cwd: String
    public let projectFolder: String
    public let resolvedExecutable: String?
    public let requestedSecrets: [RequestedSecretRowViewModel]
    public let secretRows: [String]
    public let secretCount: Int
    public let vaultGroups: [SecretVaultGroupViewModel]
    public let vaultCount: Int
    public let promptQuestion: String
    public let accessSummary: String
    public let isExpired: Bool
    public let highScopeWarning: Bool
    public let timeRemaining: String
    public let compactTimeRemaining: String
    public let reusableUses: Int
    public let scopeSummary: String
    public let allowReusableTitle: String
    public let printsEnvironmentWarning: Bool
    public let overrideEnv: Bool
    public let overriddenAliases: [String]
    public let overrideWarning: String?
    public let mutableExecutableWarning: String?
    public let cautionMessages: [String]
    public let footerMessage: String
    public let renderedText: String

    /// Builds a prompt view model without including raw secret values.
    public init(request: ApprovalRequest, now: Date = Date()) {
        title = "Secret Access Request"
        reason = Self.sanitizedDisplayText(request.reason)
        executable = Self.sanitizedDisplayText(Self.executableName(request.resolvedExecutable ?? request.command.first))
        commandArguments = Self.commandArguments(request.command)
        command = Self.commandDisplay(commandArguments)
        commandNeedsInspector = Self.commandNeedsInspector(command, arguments: commandArguments)
        commandInspectionText = Self.commandInspectionText(commandArguments)
        cwd = Self.sanitizedDisplayText(request.cwd)
        projectFolder = Self.sanitizedDisplayText(Self.displayPath(request.cwd))
        resolvedExecutable = request.resolvedExecutable.map(Self.sanitizedDisplayText)
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
        scopeSummary = Self.scopeSummary(uses: reusableUseLimit, remaining: timeRemaining, expired: isExpired)
        allowReusableTitle = Self.reuseTitle(uses: reusableUseLimit, remaining: timeRemaining, expired: isExpired)
        let warnings: WarningPresentation = Self.warningPresentation(for: request, highScopeWarning: highScopeWarning)
        printsEnvironmentWarning = warnings.printsEnvironment
        overrideEnv = request.overrideEnv
        overriddenAliases = request.overriddenAliases.map(Self.sanitizedDisplayText)
        overrideWarning = warnings.override
        mutableExecutableWarning = warnings.mutableExecutable
        cautionMessages = warnings.cautionMessages
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
                cautionMessages: cautionMessages
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
        lines.append(contentsOf: viewModel.cautionMessages)
        return lines.joined(separator: "\n")
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

    static func sanitizedDisplayText(_ value: String) -> String {
        ApprovalDisplayTextSanitizer.sanitize(value)
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
}
