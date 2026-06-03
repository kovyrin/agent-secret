import Foundation

extension ApprovalRequestViewModel {
    struct WarningPresentation: Equatable {
        let printsEnvironment: Bool
        let override: String?
        let cautionMessages: [String]
    }

    private static var environmentWarningText: String {
        "This command can print environment variables.\nOnly approve if you expected this."
    }

    private static var mutableExecutableWarningText: String {
        "This approval allows a mutable executable path.\n" +
            "Only approve if you trust the current file and its parent directories."
    }

    static func warningPresentation(
        for request: ApprovalRequest,
        highScopeWarning: Bool
    ) -> WarningPresentation {
        let printsEnvironment: Bool = printsEnvironment(for: request)
        let override: String? = overrideWarning(for: request)
        return WarningPresentation(
            printsEnvironment: printsEnvironment,
            override: override,
            cautionMessages: cautionMessages(
                printsEnvironmentWarning: printsEnvironment,
                highScopeWarning: highScopeWarning,
                overrideWarning: override,
                allowMutableExecutable: request.allowMutableExecutable
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

    private static func cautionMessages(
        printsEnvironmentWarning: Bool,
        highScopeWarning: Bool,
        overrideWarning: String?,
        allowMutableExecutable: Bool
    ) -> [String] {
        var messages: [String] = []
        if printsEnvironmentWarning, !highScopeWarning {
            messages.append(environmentWarningText)
        }
        if allowMutableExecutable {
            messages.append(mutableExecutableWarningText)
        }
        if let overrideWarning {
            messages.append(overrideWarning)
        }
        return messages
    }

    private static func printsEnvironment(for request: ApprovalRequest) -> Bool {
        isEnvironmentPrinter(resolvedExecutable: request.resolvedExecutable)
    }

    private static func isEnvironmentPrinter(resolvedExecutable: String) -> Bool {
        let executableName: String = URL(fileURLWithPath: resolvedExecutable).lastPathComponent
        return executableName == "env" || executableName == "printenv"
    }
}
