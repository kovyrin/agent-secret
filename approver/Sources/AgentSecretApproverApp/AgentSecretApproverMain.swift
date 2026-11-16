import AgentSecretApprover
import Foundation

@main
private enum AgentSecretApproverMain {
    private static let usageExitCode: Int32 = 64

    @MainActor
    static func main() async {
        do {
            let arguments: [String] = Array(CommandLine.arguments.dropFirst())
            if arguments == ["--health-check"] {
                print("Agent Secret: ok")
                exit(0)
            }
            if arguments == ["--background-updater-status"] {
                print(UpdaterSettings.registrationStatus.rawValue)
                exit(0)
            }
            if arguments == ["--suspend-background-updater"] {
                let wasEnabled = UpdaterSettings.registrationStatus == .enabled
                if wasEnabled {
                    try UpdaterSettings.unregister()
                }
                print(wasEnabled ? "enabled" : "inactive")
                exit(0)
            }
            if arguments == ["--restore-background-updater"] {
                try UpdaterSettings.bootstrapAutomaticChecks()
                exit(0)
            }
            guard let socketPath: String = try socketPath(from: arguments) else {
                do {
                    try UpdaterSettings.bootstrapAutomaticChecks()
                } catch {
                    let message = "Agent Secret: could not start background update checks: \(error)\n"
                    FileHandle.standardError.write(Data(message.utf8))
                }
                runSetupDialog()
                exit(0)
            }
            let presenter: ApprovalPresenter = AppKitApprovalPresenter()
            let controller = ApprovalController(
                clientFactory: { try SocketDaemonClient(socketPath: socketPath) },
                presenter: presenter
            )
            let terminationGuard = AutomaticTerminationGuard(reason: "Agent Secret approval in progress")
            defer { terminationGuard.invalidate() }
            _ = try await controller.run()
        } catch {
            FileHandle.standardError.write(Data("Agent Secret: \(error)\n".utf8))
            exit(usageExitCode)
        }
    }

    private static func socketPath(from arguments: [String]) throws -> String? {
        var path: String?
        var index: [String].Index = arguments.startIndex
        while index < arguments.endIndex {
            let argument: String = arguments[index]
            switch argument {
            case "--socket":
                let next: [String].Index = arguments.index(after: index)
                guard next < arguments.endIndex else {
                    throw ApproverAppError.missingValue(argument)
                }
                guard !arguments[next].hasPrefix("--") else {
                    throw ApproverAppError.missingValue(argument)
                }
                path = arguments[next]
                index = arguments.index(after: next)

            default:
                throw ApproverAppError.unsupportedArgument(argument)
            }
        }
        return path
    }
}
