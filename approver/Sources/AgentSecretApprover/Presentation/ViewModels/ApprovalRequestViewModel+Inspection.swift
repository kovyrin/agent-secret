import Foundation

extension ApprovalRequestViewModel {
    /// Full approval scope text for reviewing truncated request fields.
    var requestInspectionText: String {
        Self.requestInspectionText(
            RequestInspectionInput(
                reason: reason,
                commandArgumentRows: commandArguments.map(\.inspectorLine),
                cwd: cwd,
                resolvedExecutable: resolvedExecutable,
                allowMutableExecutable: allowMutableExecutable,
                overrideEnv: overrideEnv,
                overriddenAliases: overriddenAliases,
                resourceSectionTitle: Self.inspectionResourceSectionTitle(for: operation),
                resourceRows: resourceRows,
                scopeSummary: scopeSummary,
                sessionBindingInspectionText: sessionBindingInspectionText,
                timeRemaining: timeRemaining
            )
        )
    }
}

extension ApprovalRequestViewModel {
    private struct RequestInspectionInput {
        let reason: String
        let commandArgumentRows: [String]
        let cwd: String
        let resolvedExecutable: String
        let allowMutableExecutable: Bool
        let overrideEnv: Bool
        let overriddenAliases: [String]
        let resourceSectionTitle: String
        let resourceRows: [String]
        let scopeSummary: String
        let sessionBindingInspectionText: String?
        let timeRemaining: String
    }

    static func inspectionResourceSectionTitle(for operation: ApprovalOperation) -> String {
        switch operation {
        case .exec:
            "Secrets:"

        case .itemDescribe:
            "Item metadata:"

        case .sessionCreate:
            "Session secrets:"

        case .gcpExec, .gcpSessionCreate:
            "GCP access:"
        }
    }

    private static func requestInspectionText(_ input: RequestInspectionInput) -> String {
        var lines: [String] = [
            "Reason: \(input.reason)",
            "Command argv:"
        ]
        lines.append(contentsOf: input.commandArgumentRows)
        lines.append("Working directory: \(input.cwd)")
        lines.append("Resolved binary: \(input.resolvedExecutable)")
        lines.append("Mutable executable allowed: \(input.allowMutableExecutable ? "yes" : "no")")
        lines.append("Override existing environment: \(input.overrideEnv ? "yes" : "no")")
        if input.overriddenAliases.isEmpty {
            lines.append("Overridden aliases: none")
        } else {
            lines.append("Overridden aliases:")
            lines.append(contentsOf: input.overriddenAliases.map { "- \($0)" })
        }
        lines.append("Scope: \(input.scopeSummary)")
        if let sessionBindingInspectionText: String = input.sessionBindingInspectionText {
            lines.append("Session binding:")
            lines.append(sessionBindingInspectionText)
        }
        lines.append(input.resourceSectionTitle)
        lines.append(contentsOf: input.resourceRows)
        lines.append("Time remaining: \(input.timeRemaining)")
        return lines.joined(separator: "\n")
    }
}
