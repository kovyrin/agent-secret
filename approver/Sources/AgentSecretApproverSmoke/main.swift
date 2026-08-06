import AgentSecretApprover
import Foundation

try await runSmoke()

@MainActor
private func runSmoke() async throws {
    let arguments: [String] = Array(CommandLine.arguments.dropFirst())
    let options = try options(from: arguments)

    let request: ApprovalRequest = try request(from: options.requestPath, visual: options.visual)
    let client: SmokeDaemonClient = .init(request: request)
    let logger: RecordingLogger = .init()
    let presenter: ApprovalPresenter = if options.visual {
        AppKitApprovalPresenter()
    } else {
        SmokeDecisionPresenter(decision: options.expectedDecision ?? .deny)
    }
    let controller: ApprovalController = .init(
        client: client,
        presenter: presenter,
        logger: logger
    )
    let decision: ApprovalDecision = try await controller.run()

    try assert(decision.requestID == request.requestID, "decision request ID mismatch")
    try assert(decision.nonce == request.nonce, "decision nonce mismatch")
    if let expectedDecision = options.expectedDecision {
        try assert(decision.decision == expectedDecision, "decision kind mismatch")
    }
    if decision.decision == .approveReusable {
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

private struct SmokeOptions {
    let requestPath: String?
    let expectedDecision: ApprovalDecisionKind?
    let visual: Bool
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
        "operation": "exec",
        "allows_reusable": true,
        "allow_mutable_executable": false,
        "resources": [
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

private func visualSampleRequestData() -> Data {
    let sampleRequestJSON = """
    {
        "request_id": "req_visual_smoke",
        "nonce": "nonce_visual_smoke",
        "reason": "\(visualSmokeReason())",
        "command": ["agent-secret", "session", "create"],
        "cwd": "/Users/example/projects/sample-service",
        "expires_at": "2099-01-15T08:00:00Z",
        "access_duration_seconds": 300,
        "operation": "session_create",
        "allows_reusable": false,
        "allow_mutable_executable": false,
        "resources": [
            {
                "alias": "DEPLOY_API_TOKEN",
                "ref": "op://Example Vault/Sample Service/DEPLOY_API_TOKEN",
                "account": "example.1password.com"
            },
            {
                "alias": "OBSERVABILITY_API_TOKEN",
                "ref": "op://Example Vault/Observability/API_TOKEN",
                "account": "example.1password.com"
            }
        ],
        "resolved_executable": "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret",
        "override_env": false,
        "overridden_aliases": [],
        "reusable_uses": 1,
        "session_binding": {
            "mode": "ancestor_name",
            "ancestor_name": "codex",
            "ancestor_names": ["codex"],
            "bound_process": {
                "pid": 56029,
                "name": "codex",
                "path": "/Applications/Codex.app/Contents/MacOS/Codex"
            },
            "creator_process": {
                "pid": 56030,
                "name": "agent-secret",
                "path": "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret"
            }
        }
    }
    """
    return Data(sampleRequestJSON.utf8)
}

private func visualSmokeReason() -> String {
    [
        "Run a read-only release verification for the sample service, including configuration",
        "checks, dependency health checks, and a final deployment-plan review without allowing",
        "any write operations. The workflow records only non-secret verification metadata and",
        "keeps the approved values in the bounded session."
    ].joined(separator: " ")
}

private func assert(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() {
        throw SmokeError(message)
    }
}

private func options(from arguments: [String]) throws -> SmokeOptions {
    var requestPath: String?
    var decision: ApprovalDecisionKind = .approveReusable
    var visual = false
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

        case "--visual":
            visual = true
            index = arguments.index(after: index)

        default:
            throw SmokeError("unsupported argument \(argument)")
        }
    }
    return SmokeOptions(
        requestPath: requestPath,
        expectedDecision: visual ? nil : decision,
        visual: visual
    )
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

private func request(from path: String?, visual: Bool) throws -> ApprovalRequest {
    guard let path else {
        return try decodeRequest(from: visual ? visualSampleRequestData() : sampleRequestData())
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
