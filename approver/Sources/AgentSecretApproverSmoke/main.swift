import AgentSecretApprover
import Foundation

private let kArguments: [String] = Array(CommandLine.arguments.dropFirst())
private let kReusableUseLimit: Int = 3
private let kSampleExpiration: TimeInterval = 1_800_000_000
private let kOptions = try options(from: kArguments)

private let kRequest: ApprovalRequest = try request(from: kOptions.requestPath)
private let kClient: MockDaemonClient = .init(request: kRequest)
private let kLogger: RecordingLogger = .init()
private let kController: ApprovalController = .init(
    client: kClient,
    presenter: StaticDecisionPresenter(decision: kOptions.decision),
    logger: kLogger
)
private let kDecision: ApprovalDecision = try await kController.run()

try assert(kDecision.requestID == kRequest.requestID, "decision request ID mismatch")
try assert(kDecision.nonce == kRequest.nonce, "decision nonce mismatch")
try assert(kDecision.decision == kOptions.decision, "decision kind mismatch")
if kOptions.decision == .approveReusable {
    try assert(kDecision.reusableUses == kReusableUseLimit, "reusable use limit mismatch")
} else {
    try assert(kDecision.reusableUses == nil, "non-reusable decision carried use limit")
}

try assert(kClient.submittedDecision == kDecision, "decision was not submitted")

private let kEncodedDecision: String = try String(data: JSONEncoder().encode(kDecision), encoding: .utf8) ?? ""

try assert(!kEncodedDecision.contains("op://"), "decision encoded secret references")
try assert(!kEncodedDecision.contains("EXAMPLE_TOKEN"), "decision encoded aliases")
try assert(!kLogger.events.contains { event -> Bool in event.contains("op://") }, "logger recorded secret references")

print("approver-smoke-ok")

private func assert(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() {
        throw SmokeError(message)
    }
}

private func options(from arguments: [String]) throws -> (requestPath: String?, decision: ApprovalDecisionKind) {
    var requestPath: String?
    var decision: ApprovalDecisionKind = .approveReusable
    var index: [String].Index = arguments.startIndex
    while index < arguments.endIndex {
        let argument: String = arguments[index]
        switch argument {
        case "--mock-request":
            let result = try value(after: index, flag: argument, in: arguments)
            requestPath = result.value
            index = result.nextIndex

        case "--mock-decision":
            let result = try value(after: index, flag: argument, in: arguments)
            decision = try decisionKind(from: result.value)
            index = result.nextIndex

        default:
            throw SmokeError("unsupported argument \(argument)")
        }
    }
    return (requestPath, decision)
}

private func value(
    after index: [String].Index,
    flag: String,
    in arguments: [String]
) throws -> (value: String, nextIndex: [String].Index) {
    let valueIndex: [String].Index = arguments.index(after: index)
    guard valueIndex < arguments.endIndex else {
        throw SmokeError("missing value for \(flag)")
    }
    guard !arguments[valueIndex].hasPrefix("--") else {
        throw SmokeError("missing value for \(flag)")
    }
    return (arguments[valueIndex], arguments.index(after: valueIndex))
}

private func decisionKind(from raw: String) throws -> ApprovalDecisionKind {
    switch raw {
    case "approve", "approve-once":
        .approveOnce

    case "deny":
        .deny

    case "reuse", "approve-reusable":
        .approveReusable

    case "timeout":
        .timeout

    default:
        throw SmokeError("invalid mock decision \(raw)")
    }
}

private func request(from path: String?) throws -> ApprovalRequest {
    guard let path else {
        return ApprovalRequest(
            requestID: "req_123",
            nonce: "nonce_456",
            reason: "Run Terraform plan for staging",
            command: ["/opt/homebrew/bin/terraform", "plan"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: kSampleExpiration),
            secrets: [
                RequestedSecret(
                    alias: "EXAMPLE_TOKEN",
                    ref: "op://Example Vault/Example Item/token",
                    account: "Work"
                )
            ]
        )
    }

    let data: Data = if path == "-" {
        FileHandle.standardInput.readDataToEndOfFile()
    } else {
        try Data(contentsOf: URL(fileURLWithPath: path))
    }
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    return try decoder.decode(ApprovalRequest.self, from: data)
}
