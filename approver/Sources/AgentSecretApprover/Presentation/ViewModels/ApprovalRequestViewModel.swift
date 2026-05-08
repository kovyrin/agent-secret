import Foundation

/// Sanitized text prepared for the approval UI.
struct ApprovalRequestViewModel: Equatable {
    private struct ResourcePresentation {
        let rows: [RequestedResourceRowViewModel]
        let rowText: [String]
        let count: Int
        let vaultGroups: [ResourceVaultGroupViewModel]
        let vaultCount: Int
    }

    private struct SelfRenderInput {
        let title: String
        let reason: String
        let command: String
        let commandArgumentRows: [String]
        let cwd: String
        let scopeSummary: String
        let resolvedExecutable: String
        let resourceRows: [String]
        let timeRemaining: String
        let cautionMessages: [String]
    }

    private static let highScopeResourceThreshold: Int = 6
    private static let commandInspectorThreshold: Int = 96
    private static let secondsPerMinute: Int = 60

    let title: String
    let operation: ApprovalOperation
    let reason: String
    let command: String
    let commandNeedsInspector: Bool
    let commandInspectionText: String
    let commandArguments: [CommandArgumentViewModel]
    let executable: String
    let cwd: String
    let projectFolder: String
    let resolvedExecutable: String
    let requestedResources: [RequestedResourceRowViewModel]
    let requestedResourcesHeading: String
    let resourceRows: [String]
    let resourceCount: Int
    let vaultGroups: [ResourceVaultGroupViewModel]
    let vaultCount: Int
    let promptQuestion: String
    let accessSummary: String
    let isExpired: Bool
    let highScopeWarning: Bool
    let timeRemaining: String
    let compactTimeRemaining: String
    let reusableUses: Int
    let allowsReusableApproval: Bool
    let scopeSummary: String
    let allowReusableTitle: String
    let printsEnvironmentWarning: Bool
    let overrideEnv: Bool
    let overriddenAliases: [String]
    let overrideWarning: String?
    let cautionMessages: [String]
    let footerMessage: String
    let renderedText: String

    /// Builds a prompt view model without including raw secret values.
    init(request: ApprovalRequest, now: Date = Date()) {
        (operation, title) = (request.operation, Self.title(for: request.operation))
        reason = Self.sanitizedDisplayText(request.reason)
        executable = Self.sanitizedDisplayText(Self.executableName(request.resolvedExecutable))
        commandArguments = Self.commandArguments(request.command)
        command = Self.commandDisplay(commandArguments)
        commandNeedsInspector = Self.commandNeedsInspector(command, arguments: commandArguments)
        commandInspectionText = Self.commandInspectionText(commandArguments)
        cwd = Self.sanitizedDisplayText(request.cwd)
        projectFolder = Self.sanitizedDisplayText(Self.displayPath(request.cwd))
        resolvedExecutable = Self.sanitizedDisplayText(request.resolvedExecutable)
        let resourcePresentation: ResourcePresentation = Self.resourcePresentation(for: request.resources)
        requestedResources = resourcePresentation.rows
        requestedResourcesHeading = Self.requestedResourcesHeading(
            operation: request.operation,
            resourceCount: resourcePresentation.count
        )
        resourceRows = resourcePresentation.rowText
        resourceCount = resourcePresentation.count
        vaultGroups = resourcePresentation.vaultGroups
        vaultCount = resourcePresentation.vaultCount
        let copy: CopyPresentation = Self.copyPresentation(for: request, count: resourcePresentation.count, now: now)
        (isExpired, timeRemaining, compactTimeRemaining) = (copy.isExpired, copy.timeRemaining, copy.timeRemaining)
        (promptQuestion, accessSummary) = (copy.promptQuestion, copy.accessSummary)
        highScopeWarning = request.operation == .exec && resourcePresentation.count >= Self.highScopeResourceThreshold
        (reusableUses, allowsReusableApproval) = (request.reusableUses, request.allowsReusable)
        (scopeSummary, allowReusableTitle) = (copy.scopeSummary, copy.allowReusableTitle)
        let warnings: WarningPresentation = Self.warningPresentation(for: request, highScopeWarning: highScopeWarning)
        (printsEnvironmentWarning, overrideWarning, cautionMessages) = (
            warnings.printsEnvironment,
            warnings.override,
            warnings.cautionMessages
        )
        overrideEnv = request.overrideEnv
        overriddenAliases = request.overriddenAliases.map(Self.sanitizedDisplayText)
        footerMessage = copy.footerMessage
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
                resourceRows: resourceRows,
                timeRemaining: timeRemaining,
                cautionMessages: cautionMessages
            )
        )
    }

    private static func resourcePresentation(for resources: [RequestedResource]) -> ResourcePresentation {
        let rows: [RequestedResourceRowViewModel] = resources.map { resource -> RequestedResourceRowViewModel in
            RequestedResourceRowViewModel(alias: resource.alias, ref: resource.ref, account: resource.account)
        }
        let rowText: [String] = rows.map { resource -> String in
            Self.resourceRowText(resource)
        }
        let vaultGroups: [ResourceVaultGroupViewModel] = Self.vaultGroups(for: rows)
        return ResourcePresentation(
            rows: rows,
            rowText: rowText,
            count: rows.count,
            vaultGroups: vaultGroups,
            vaultCount: vaultGroups.count
        )
    }

    private static func vaultGroups(for rows: [RequestedResourceRowViewModel]) -> [ResourceVaultGroupViewModel] {
        var groups: [ResourceVaultGroupViewModel] = []
        var groupIndexesByScope: [String: Int] = [:]
        for row in rows {
            if let index: Int = groupIndexesByScope[row.vaultScopeName] {
                var group: ResourceVaultGroupViewModel = groups[index]
                group = ResourceVaultGroupViewModel(vaultName: group.vaultName, resources: group.resources + [row])
                groups[index] = group
            } else {
                groupIndexesByScope[row.vaultScopeName] = groups.count
                groups.append(ResourceVaultGroupViewModel(vaultName: row.vaultScopeName, resources: [row]))
            }
        }
        return groups
    }

    private static func resourceRowText(_ resource: RequestedResourceRowViewModel) -> String {
        "\(resource.alias) [\(resource.accountLabel)] -> \(resource.ref)"
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
        lines.append("Resolved binary: \(viewModel.resolvedExecutable)")
        lines.append(request.operation == .itemDescribe ? "Item metadata:" : "Secrets:")
        lines.append(contentsOf: viewModel.resourceRows)
        lines.append("Time remaining: \(viewModel.timeRemaining)")
        if request.allowsReusable {
            lines.append(
                "Reusable approval keeps values in daemon memory for this window " +
                    "and is limited to \(request.reusableUses) uses."
            )
        } else {
            lines.append("Approval is limited to one metadata lookup.")
        }
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

    private static func executableName(_ path: String) -> String {
        URL(fileURLWithPath: path).lastPathComponent
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
