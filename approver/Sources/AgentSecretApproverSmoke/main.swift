import AgentSecretApprover
import Foundation

let request = ApprovalRequest(
    requestID: "req_123",
    nonce: "nonce_456",
    reason: "Run Terraform plan for staging",
    command: ["/opt/homebrew/bin/terraform", "plan"],
    cwd: "/tmp/project",
    expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
    secrets: [
        RequestedSecret(
            alias: "EXAMPLE_TOKEN",
            ref: "op://Example Vault/Example Item/token"
        )
    ]
)

let client = MockDaemonClient(request: request)
private let logger = RecordingLogger()
let controller = ApprovalController(
    client: client,
    presenter: StaticDecisionPresenter(decision: .approveReusable),
    logger: logger
)
let decision = try controller.run()

try assert(decision.requestID == request.requestID, "decision request ID mismatch")
try assert(decision.nonce == request.nonce, "decision nonce mismatch")
try assert(decision.decision == .approveReusable, "decision kind mismatch")
try assert(decision.reusableUses == 3, "reusable use limit mismatch")
try assert(client.submittedDecision == decision, "decision was not submitted")

let encoded = String(data: try JSONEncoder().encode(decision), encoding: .utf8) ?? ""
try assert(!encoded.contains("op://"), "decision encoded secret references")
try assert(!encoded.contains("EXAMPLE_TOKEN"), "decision encoded aliases")
try assert(!logger.events.contains { $0.contains("op://") }, "logger recorded secret references")

print("approver-smoke-ok")

private final class RecordingLogger: ApprovalLogger {
    private(set) var events: [String] = []

    func record(_ event: String, requestID: String?) {
        events.append("\(event):\(requestID ?? "none")")
    }
}

private func assert(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() {
        throw SmokeError(message)
    }
}

private struct SmokeError: Error, CustomStringConvertible {
    var description: String

    init(_ description: String) {
        self.description = description
    }
}
