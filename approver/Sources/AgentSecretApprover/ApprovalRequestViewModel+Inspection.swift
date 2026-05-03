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
                secretRows: secretRows,
                scopeSummary: scopeSummary,
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
        let resolvedExecutable: String?
        let secretRows: [String]
        let scopeSummary: String
        let timeRemaining: String
    }

    private static func requestInspectionText(_ input: RequestInspectionInput) -> String {
        var lines: [String] = [
            "Reason: \(input.reason)",
            "Command argv:"
        ]
        lines.append(contentsOf: input.commandArgumentRows)
        lines.append("Working directory: \(input.cwd)")
        lines.append("Resolved binary: \(input.resolvedExecutable ?? "not resolved")")
        lines.append("Scope: \(input.scopeSummary)")
        lines.append("Secrets:")
        lines.append(contentsOf: input.secretRows)
        lines.append("Time remaining: \(input.timeRemaining)")
        return lines.joined(separator: "\n")
    }
}
