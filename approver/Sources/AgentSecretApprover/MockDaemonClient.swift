import Foundation

/// In-memory daemon client used by tests and local smoke runs.
public final class MockDaemonClient: ApprovalDaemonClient {
    private let request: ApprovalRequest

    /// Decision submitted by the controller.
    public private(set) var submittedDecision: ApprovalDecision?

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
        submittedDecision = decision
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
