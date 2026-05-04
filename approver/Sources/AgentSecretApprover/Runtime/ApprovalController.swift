import Foundation

/// Coordinates value-free logging around daemon I/O while blocking socket work stays off the main actor.
public final class ApprovalController {
    private let client: ApprovalDaemonClientWorker
    private let presenter: ApprovalPresenter
    private let logger: ApprovalLogger
    private let now: () -> Date

    /// Use for in-memory clients; socket clients should prefer the factory initializer.
    public convenience init(
        client: ApprovalDaemonClient,
        presenter: ApprovalPresenter,
        logger: ApprovalLogger = UnifiedApprovalLogger(category: "decisions"),
        now: @escaping () -> Date = Date.init
    ) {
        self.init(clientFactory: { client }, presenter: presenter, logger: logger, now: now)
    }

    /// Creates a controller that builds the daemon client on the background worker queue.
    public init(
        clientFactory: @escaping () throws -> ApprovalDaemonClient,
        presenter: ApprovalPresenter,
        logger: ApprovalLogger = UnifiedApprovalLogger(category: "decisions"),
        now: @escaping () -> Date = Date.init
    ) {
        client = ApprovalDaemonClientWorker(clientFactory: clientFactory)
        self.presenter = presenter
        self.logger = logger
        self.now = now
    }

    /// Runs on the main actor because presenters may open AppKit UI.
    @preconcurrency
    @MainActor
    public func run() async throws -> ApprovalDecision {
        logger.record("approval_request_fetch_started", requestID: nil)
        let request: ApprovalRequest = try await client.fetchPendingRequest()
        logger.record("approval_request_loaded", requestID: request.requestID)

        let presentedDecisionKind: ApprovalDecisionKind = presenter.decide(for: request)
        let decisionKind: ApprovalDecisionKind = ApprovalPromptExpiration(expiresAt: request.expiresAt)
            .guardDecision(presentedDecisionKind, at: now())
        let decision: ApprovalDecision = decision(for: decisionKind, request: request)

        logger.record("approval_decision_submit_started", requestID: request.requestID)
        do {
            try client.submitBlocking(decision)
        } catch {
            logger.record("approval_decision_submit_failed", requestID: request.requestID)
            throw error
        }
        logger.record("approval_decision_submitted", requestID: request.requestID)
        return decision
    }

    private func decision(
        for decisionKind: ApprovalDecisionKind,
        request: ApprovalRequest
    ) -> ApprovalDecision {
        switch decisionKind {
        case .approveOnce:
            .approveOnce(for: request)

        case .approveReusable:
            .approveReusable(for: request)

        case .deny:
            .deny(for: request)

        case .timeout:
            .timeout(for: request)
        }
    }
}
