import Foundation

public final class MockDaemonClient: ApprovalDaemonClient {
    private let lock = NSLock()
    private let request: ApprovalRequest
    private var lastSubmittedDecision: ApprovalDecision?

    public var submittedDecision: ApprovalDecision? {
        lock.lock()
        defer { lock.unlock() }
        return lastSubmittedDecision
    }

    public init(request: ApprovalRequest) {
        self.request = request
    }

    public func fetchPendingRequest() -> ApprovalRequest {
        request
    }

    public func submit(_ decision: ApprovalDecision) {
        lock.lock()
        defer { lock.unlock() }
        lastSubmittedDecision = decision
    }
}
