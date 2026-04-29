import AgentSecretApprover
import Foundation

private enum ApproverAppError: Error, CustomStringConvertible {
    case invalidDecision(String)
    case missingSocket
    case missingValue(String)

    var description: String {
        switch self {
        case let .invalidDecision(value):
            "invalid mock decision \(value)"

        case .missingSocket:
            "missing --socket for daemon approval mode"

        case let .missingValue(flag):
            "missing value for \(flag)"
        }
    }
}

private let kDefaultMockRequestTTL: TimeInterval = 120
private let kUsageExitCode: Int32 = 64
private let kArguments: [String] = Array(CommandLine.arguments.dropFirst())

do {
    let presenter: ApprovalPresenter = if let mockDecision: ApprovalDecisionKind = try mockDecisionFromArguments(
        kArguments
    ) {
        StaticDecisionPresenter(decision: mockDecision)
    } else {
        AppKitApprovalPresenter()
    }
    let client: ApprovalDaemonClient = if let socketPath: String = try value(for: "--socket", in: kArguments) {
        try SocketDaemonClient(socketPath: socketPath)
    } else if hasMockRequest(kArguments) {
        try MockDaemonClient(request: requestFromArguments(kArguments))
    } else {
        throw ApproverAppError.missingSocket
    }
    let controller = ApprovalController(client: client, presenter: presenter)
    let decision: ApprovalDecision = try controller.run()

    if hasMockRequest(kArguments) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data: Data = try encoder.encode(decision)
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }
} catch {
    FileHandle.standardError.write(Data("agent-secret-approver: \(error)\n".utf8))
    exit(kUsageExitCode)
}

private func hasMockRequest(_ arguments: [String]) -> Bool {
    arguments.contains("--mock-request")
}

private func mockDecisionFromArguments(_ arguments: [String]) throws -> ApprovalDecisionKind? {
    guard let raw: String = try value(for: "--mock-decision", in: arguments) else {
        return nil
    }

    switch raw {
    case "approve", "approve-once":
        return .approveOnce

    case "deny":
        return .deny

    case "reuse", "approve-reusable":
        return .approveReusable

    case "timeout":
        return .timeout

    default:
        throw ApproverAppError.invalidDecision(raw)
    }
}

private func requestFromArguments(_ arguments: [String]) throws -> ApprovalRequest {
    if let path: String = try value(for: "--mock-request", in: arguments) {
        let data: Data = if path == "-" {
            FileHandle.standardInput.readDataToEndOfFile()
        } else {
            try Data(contentsOf: URL(fileURLWithPath: path))
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(ApprovalRequest.self, from: data)
    }

    return ApprovalRequest(
        requestID: "mock-request",
        nonce: "mock-nonce",
        reason: "Approve a mock agent-secret request",
        command: ["/usr/bin/env", "terraform", "plan"],
        cwd: FileManager.default.currentDirectoryPath,
        expiresAt: Date().addingTimeInterval(kDefaultMockRequestTTL),
        secrets: [
            RequestedSecret(
                alias: "EXAMPLE_TOKEN",
                ref: "op://Example Vault/Example Item/token"
            )
        ]
    )
}

private func value(for flag: String, in arguments: [String]) throws -> String? {
    guard let index: [String].Index = arguments.firstIndex(of: flag) else {
        return nil
    }

    let next: [String].Index = arguments.index(after: index)
    guard next < arguments.endIndex else {
        throw ApproverAppError.missingValue(flag)
    }

    return arguments[next]
}
