import AgentSecretApprover
import Foundation

final class SmokeDaemonClient: ApprovalDaemonClient {
    private let lock = NSLock()
    private let request: ApprovalRequest
    private var lastSubmittedDecision: ApprovalDecision?

    var submittedDecision: ApprovalDecision? {
        lock.lock()
        defer { lock.unlock() }
        return lastSubmittedDecision
    }

    init(request: ApprovalRequest) {
        self.request = request
    }

    func fetchPendingRequest() -> ApprovalRequest {
        request
    }

    func submit(_ decision: ApprovalDecision) {
        lock.lock()
        defer { lock.unlock() }
        lastSubmittedDecision = decision
    }
}
