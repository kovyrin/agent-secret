import AgentSecretApprover
import Foundation

private enum ApproverAppError: Error, CustomStringConvertible {
    case missingValue(String)
    case unsupportedArgument(String)

    var description: String {
        switch self {
        case let .missingValue(flag):
            "missing value for \(flag)"

        case let .unsupportedArgument(argument):
            "unsupported argument \(argument)"
        }
    }
}

private let kUsageExitCode: Int32 = 64
private let kArguments: [String] = Array(CommandLine.arguments.dropFirst())

do {
    if kArguments == ["--health-check"] {
        print("agent-secret-approver: ok")
        exit(0)
    }
    guard let socketPath: String = try socketPath(from: kArguments) else {
        MainActor.assumeIsolated {
            runSetupDialog()
        }
        exit(0)
    }
    let presenter: ApprovalPresenter = AppKitApprovalPresenter()
    let client: ApprovalDaemonClient = try SocketDaemonClient(socketPath: socketPath)
    let controller = ApprovalController(client: client, presenter: presenter)
    _ = try controller.run()
} catch {
    FileHandle.standardError.write(Data("agent-secret-approver: \(error)\n".utf8))
    exit(kUsageExitCode)
}

private func socketPath(from arguments: [String]) throws -> String? {
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
