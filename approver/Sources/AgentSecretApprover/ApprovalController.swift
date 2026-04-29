import Foundation

/// Runs the approval fetch, presentation, and submission flow.
public final class ApprovalController {
    private static let reusableDecisionUses: Int = 3

    private let client: ApprovalDaemonClient
    private let presenter: ApprovalPresenter
    private let logger: ApprovalLogger

    /// Creates a controller with daemon, presenter, and metadata logger dependencies.
    public init(
        client: ApprovalDaemonClient,
        presenter: ApprovalPresenter,
        logger: ApprovalLogger = UnifiedApprovalLogger(category: "decisions")
    ) {
        self.client = client
        self.presenter = presenter
        self.logger = logger
    }

    /// Executes one approval interaction and returns the submitted decision.
    public func run() throws -> ApprovalDecision {
        logger.record("approval_request_fetch_started", requestID: nil)
        let request: ApprovalRequest = try client.fetchPendingRequest()
        logger.record("approval_request_loaded", requestID: request.requestID)

        let decisionKind: ApprovalDecisionKind = presenter.decide(for: request)
        let reusableUses: Int? = decisionKind == .approveReusable ? Self.reusableDecisionUses : nil
        let decision = ApprovalDecision(
            requestID: request.requestID,
            nonce: request.nonce,
            decision: decisionKind,
            reusableUses: reusableUses
        )

        try client.submit(decision)
        logger.record("approval_decision_submitted", requestID: request.requestID)
        return decision
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
