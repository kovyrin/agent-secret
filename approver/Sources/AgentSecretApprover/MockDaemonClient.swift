import Foundation

/// In-memory daemon client used by tests and local smoke runs.
public final class MockDaemonClient: ApprovalDaemonClient {
    private let lock = NSLock()
    private let request: ApprovalRequest
    private var lastSubmittedDecision: ApprovalDecision?

    /// Decision submitted by the controller.
    public var submittedDecision: ApprovalDecision? {
        lock.lock()
        defer { lock.unlock() }
        return lastSubmittedDecision
    }

    /// Creates a mock daemon client with one pending request.
    public init(request: ApprovalRequest) {
        self.request = request
    }

    /// Returns the configured pending request.
    public func fetchPendingRequest() -> ApprovalRequest {
        request
    }

    /// Captures a submitted decision for assertions.
    public func submit(_ decision: ApprovalDecision) {
        lock.lock()
        defer { lock.unlock() }
        lastSubmittedDecision = decision
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
