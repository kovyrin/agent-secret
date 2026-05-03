import Foundation

extension ApprovalRequestViewModel {
    struct WarningPresentation: Equatable {
        let printsEnvironment: Bool
        let override: String?
        let mutableExecutable: String?
        let cautionMessages: [String]
    }

    private static var environmentWarningText: String {
        "This command can print environment variables.\nOnly approve if you expected this."
    }

    static func warningPresentation(
        for request: ApprovalRequest,
        highScopeWarning: Bool
    ) -> WarningPresentation {
        let printsEnvironment: Bool = environmentWarning(for: request)
        let mutableExecutable: String? = mutableExecutableWarning(for: request)
        return WarningPresentation(
            printsEnvironment: printsEnvironment,
            override: overrideWarning(for: request),
            mutableExecutable: mutableExecutable,
            cautionMessages: cautionMessages(
                printsEnvironmentWarning: printsEnvironment,
                highScopeWarning: highScopeWarning,
                mutableExecutableWarning: mutableExecutable
            )
        )
    }

    private static func overrideWarning(for request: ApprovalRequest) -> String? {
        guard request.overrideEnv, !request.overriddenAliases.isEmpty else {
            return nil
        }
        let aliases: [String] = request.overriddenAliases.map(Self.sanitizedDisplayText)
        return "Will replace existing variables: \(aliases.joined(separator: ", "))"
    }

    private static func mutableExecutableWarning(for request: ApprovalRequest) -> String? {
        guard request.allowMutableExecutable else {
            return nil
        }
        return "Mutable executable opt-in: command path may be replaceable before launch."
    }

    private static func cautionMessages(
        printsEnvironmentWarning: Bool,
        highScopeWarning: Bool,
        mutableExecutableWarning: String?
    ) -> [String] {
        var messages: [String] = []
        if printsEnvironmentWarning, !highScopeWarning {
            messages.append(environmentWarningText)
        }
        if let mutableExecutableWarning {
            messages.append(mutableExecutableWarning)
        }
        return messages
    }

    private static func environmentWarning(for request: ApprovalRequest) -> Bool {
        environmentPrinter(command: request.command, resolvedExecutable: request.resolvedExecutable)
    }

    private static func environmentPrinter(command: [String], resolvedExecutable: String?) -> Bool {
        let executableName: String = URL(fileURLWithPath: resolvedExecutable ?? command.first ?? "")
            .lastPathComponent
        return executableName == "env" || executableName == "printenv"
    }
}
