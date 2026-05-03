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
                print("agent-secret-approver: ok")
                exit(0)
            }
            guard let socketPath: String = try socketPath(from: arguments) else {
                runSetupDialog()
                exit(0)
            }
            let presenter: ApprovalPresenter = AppKitApprovalPresenter()
            let client: ApprovalDaemonClient = try SocketDaemonClient(socketPath: socketPath)
            let controller = ApprovalController(client: client, presenter: presenter)
            _ = try await controller.run()
        } catch {
            FileHandle.standardError.write(Data("agent-secret-approver: \(error)\n".utf8))
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
