import Foundation

/// Runs the approval fetch, presentation, and submission flow.
public final class ApprovalController {
    private let client: ApprovalDaemonClientWorker
    private let presenter: ApprovalPresenter
    private let logger: ApprovalLogger

    /// Creates a controller with daemon, presenter, and metadata logger dependencies.
    public convenience init(
        client: ApprovalDaemonClient,
        presenter: ApprovalPresenter,
        logger: ApprovalLogger = UnifiedApprovalLogger(category: "decisions")
    ) {
        self.init(clientFactory: { client }, presenter: presenter, logger: logger)
    }

    /// Creates a controller that builds the daemon client on the background worker queue.
    public init(
        clientFactory: @escaping () throws -> ApprovalDaemonClient,
        presenter: ApprovalPresenter,
        logger: ApprovalLogger = UnifiedApprovalLogger(category: "decisions")
    ) {
        client = ApprovalDaemonClientWorker(clientFactory: clientFactory)
        self.presenter = presenter
        self.logger = logger
    }

    /// Executes one approval interaction and returns the submitted decision.
    @preconcurrency
    @MainActor
    public func run() async throws -> ApprovalDecision {
        logger.record("approval_request_fetch_started", requestID: nil)
        let request: ApprovalRequest = try await client.fetchPendingRequest()
        logger.record("approval_request_loaded", requestID: request.requestID)

        let decisionKind: ApprovalDecisionKind = presenter.decide(for: request)
        let reusableUses: Int? = decisionKind == .approveReusable ? request.reusableUses : nil
        let decision = ApprovalDecision(
            requestID: request.requestID,
            nonce: request.nonce,
            decision: decisionKind,
            reusableUses: reusableUses
        )

        try await client.submit(decision)
        logger.record("approval_decision_submitted", requestID: request.requestID)
        return decision
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
