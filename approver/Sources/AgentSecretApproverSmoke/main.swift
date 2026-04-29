import AgentSecretApprover
import Foundation

private let kReusableUseLimit: Int = 3
private let kSampleExpiration: TimeInterval = 1_800_000_000

private let kRequest: ApprovalRequest = .init(
    requestID: "req_123",
    nonce: "nonce_456",
    reason: "Run Terraform plan for staging",
    command: ["/opt/homebrew/bin/terraform", "plan"],
    cwd: "/tmp/project",
    expiresAt: Date(timeIntervalSince1970: kSampleExpiration),
    secrets: [
        RequestedSecret(
            alias: "EXAMPLE_TOKEN",
            ref: "op://Example Vault/Example Item/token"
        )
    ]
)

private let kClient: MockDaemonClient = .init(request: kRequest)
private let kLogger: RecordingLogger = .init()
private let kController: ApprovalController = .init(
    client: kClient,
    presenter: StaticDecisionPresenter(decision: .approveReusable),
    logger: kLogger
)
private let kDecision: ApprovalDecision = try kController.run()

try assert(kDecision.requestID == kRequest.requestID, "decision request ID mismatch")
try assert(kDecision.nonce == kRequest.nonce, "decision nonce mismatch")
try assert(kDecision.decision == .approveReusable, "decision kind mismatch")
try assert(kDecision.reusableUses == kReusableUseLimit, "reusable use limit mismatch")
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
