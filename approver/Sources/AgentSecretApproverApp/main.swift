import AgentSecretApprover
import Foundation

enum ApproverAppError: Error, CustomStringConvertible {
    case missingValue(String)
    case invalidDecision(String)
    case missingSocket

    var description: String {
        switch self {
        case let .missingValue(flag):
            "missing value for \(flag)"
        case let .invalidDecision(value):
            "invalid mock decision \(value)"
        case .missingSocket:
            "missing --socket for daemon approval mode"
        }
    }
}

let arguments = Array(CommandLine.arguments.dropFirst())

do {
    let presenter: ApprovalPresenter = if let mockDecision = try mockDecisionFromArguments(arguments) {
        StaticDecisionPresenter(decision: mockDecision)
    } else {
        AppKitApprovalPresenter()
    }
    let client: ApprovalDaemonClient = if let socketPath = try value(for: "--socket", in: arguments) {
        try SocketDaemonClient(socketPath: socketPath)
    } else if hasMockRequest(arguments) {
        MockDaemonClient(request: try requestFromArguments(arguments))
    } else {
        throw ApproverAppError.missingSocket
    }
    let controller = ApprovalController(client: client, presenter: presenter)
    let decision = try controller.run()

    if hasMockRequest(arguments) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(decision)
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }
} catch {
    FileHandle.standardError.write(Data("agent-secret-approver: \(error)\n".utf8))
    exit(64)
}

func requestFromArguments(_ arguments: [String]) throws -> ApprovalRequest {
    if let path = try value(for: "--mock-request", in: arguments) {
        let data = path == "-"
            ? FileHandle.standardInput.readDataToEndOfFile()
            : try Data(contentsOf: URL(fileURLWithPath: path))
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
        expiresAt: Date().addingTimeInterval(120),
        secrets: [
            RequestedSecret(
                alias: "EXAMPLE_TOKEN",
                ref: "op://Example Vault/Example Item/token"
            )
        ]
    )
}

func hasMockRequest(_ arguments: [String]) -> Bool {
    arguments.contains("--mock-request")
}

func mockDecisionFromArguments(_ arguments: [String]) throws -> ApprovalDecisionKind? {
    guard let raw = try value(for: "--mock-decision", in: arguments) else {
        return nil
    }

    switch raw {
    case "approve", "approve-once":
        return .approveOnce
    case "reuse", "approve-reusable":
        return .approveReusable
    case "deny":
        return .deny
    case "timeout":
        return .timeout
    default:
        throw ApproverAppError.invalidDecision(raw)
    }
}

func value(for flag: String, in arguments: [String]) throws -> String? {
    guard let index = arguments.firstIndex(of: flag) else {
        return nil
    }

    let next = arguments.index(after: index)
    guard next < arguments.endIndex else {
        throw ApproverAppError.missingValue(flag)
    }

    return arguments[next]
}
