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
            if arguments.first == "--gcp-oauth-login" {
                let prompt = try gcpOAuthLoginPrompt(from: Array(arguments.dropFirst()))
                AppKitGCPOAuthLoginPromptPresenter.run(prompt: prompt)
                exit(0)
            }
            guard let socketPath: String = try socketPath(from: arguments) else {
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

    private static func gcpOAuthLoginPrompt(from arguments: [String]) throws -> GCPOAuthLoginPrompt {
        var authorizationURL: URL?
        var googleAccount = ""
        var expectedEmail: String?
        var scopes: [String] = []
        var index: [String].Index = arguments.startIndex
        while index < arguments.endIndex {
            let argument: String = arguments[index]
            switch argument {
            case "--url":
                let next: [String].Index = try valueIndex(after: index, in: arguments, argument: argument)
                guard let parsed = URL(string: arguments[next]), parsed.scheme != nil else {
                    throw ApproverAppError.unsupportedArgument("invalid --url")
                }
                authorizationURL = parsed
                index = arguments.index(after: next)

            case "--google-account":
                let next: [String].Index = try valueIndex(after: index, in: arguments, argument: argument)
                googleAccount = arguments[next]
                index = arguments.index(after: next)

            case "--expected-email":
                let next: [String].Index = try valueIndex(after: index, in: arguments, argument: argument)
                expectedEmail = arguments[next]
                index = arguments.index(after: next)

            case "--scope":
                let next: [String].Index = try valueIndex(after: index, in: arguments, argument: argument)
                scopes.append(arguments[next])
                index = arguments.index(after: next)

            default:
                throw ApproverAppError.unsupportedArgument(argument)
            }
        }
        guard let authorizationURL else {
            throw ApproverAppError.missingValue("--url")
        }
        return GCPOAuthLoginPrompt(
            authorizationURL: authorizationURL,
            googleAccount: googleAccount,
            expectedEmail: expectedEmail,
            scopes: scopes
        )
    }

    private static func valueIndex(
        after index: [String].Index,
        in arguments: [String],
        argument: String
    ) throws -> [String].Index {
        let next: [String].Index = arguments.index(after: index)
        guard next < arguments.endIndex else {
            throw ApproverAppError.missingValue(argument)
        }
        guard !arguments[next].hasPrefix("--") else {
            throw ApproverAppError.missingValue(argument)
        }
        return next
    }
}
