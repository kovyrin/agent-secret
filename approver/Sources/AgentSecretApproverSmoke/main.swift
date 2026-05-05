import AgentSecretApprover
import Foundation

try await runSmoke()

@MainActor
private func runSmoke() async throws {
    let arguments: [String] = Array(CommandLine.arguments.dropFirst())
    let options = try options(from: arguments)

    let request: ApprovalRequest = try request(from: options.requestPath)
    let client: SmokeDaemonClient = .init(request: request)
    let logger: RecordingLogger = .init()
    let controller: ApprovalController = .init(
        client: client,
        presenter: SmokeDecisionPresenter(decision: options.decision),
        logger: logger
    )
    let decision: ApprovalDecision = try await controller.run()

    try assert(decision.requestID == request.requestID, "decision request ID mismatch")
    try assert(decision.nonce == request.nonce, "decision nonce mismatch")
    try assert(decision.decision == options.decision, "decision kind mismatch")
    if options.decision == .approveReusable {
        try assert(decision.reusableUses == request.reusableUses, "reusable use limit mismatch")
    } else {
        try assert(decision.reusableUses == nil, "non-reusable decision carried use limit")
    }

    try assert(client.submittedDecision == decision, "decision was not submitted")

    let encodedDecision: String = try String(data: JSONEncoder().encode(decision), encoding: .utf8) ?? ""

    try assert(!encodedDecision.contains("op://"), "decision encoded secret references")
    try assert(!encodedDecision.contains("EXAMPLE_TOKEN"), "decision encoded aliases")
    try assert(
        !logger.events.contains { event -> Bool in event.contains("op://") },
        "logger recorded secret references"
    )

    print("approver-smoke-ok")
}

private func sampleRequestData() -> Data {
    let sampleRequestJSON = """
    {
        "request_id": "req_123",
        "nonce": "nonce_456",
        "reason": "Run Terraform plan for staging",
        "command": ["/opt/homebrew/bin/terraform", "plan"],
        "cwd": "/tmp/project",
        "expires_at": "2027-01-15T08:00:00Z",
        "secrets": [
            {
                "alias": "EXAMPLE_TOKEN",
                "ref": "op://Example Vault/Example Item/token",
                "account": "Work"
            }
        ],
        "resolved_executable": "/opt/homebrew/bin/terraform",
        "override_env": false,
        "overridden_aliases": [],
        "reusable_uses": 3
    }
    """
    return Data(sampleRequestJSON.utf8)
}

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
        return try decodeRequest(from: sampleRequestData())
    }

    let data: Data = if path == "-" {
        FileHandle.standardInput.readDataToEndOfFile()
    } else {
        try Data(contentsOf: URL(fileURLWithPath: path))
    }
    return try decodeRequest(from: data)
}

private func decodeRequest(from data: Data) throws -> ApprovalRequest {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    return try decoder.decode(ApprovalRequest.self, from: data)
}
