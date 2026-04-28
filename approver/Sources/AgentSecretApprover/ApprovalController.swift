import Foundation

public protocol ApprovalDaemonClient {
    func fetchPendingRequest() throws -> ApprovalRequest
    func submit(_ decision: ApprovalDecision) throws
}

public protocol ApprovalPresenter {
    func decide(for request: ApprovalRequest) -> ApprovalDecisionKind
}

public protocol ApprovalLogger {
    func record(_ event: String, requestID: String?)
}

public final class ApprovalController {
    private let client: ApprovalDaemonClient
    private let presenter: ApprovalPresenter
    private let logger: ApprovalLogger

    public init(
        client: ApprovalDaemonClient,
        presenter: ApprovalPresenter,
        logger: ApprovalLogger = UnifiedApprovalLogger(category: "decisions")
    ) {
        self.client = client
        self.presenter = presenter
        self.logger = logger
    }

    public func run() throws -> ApprovalDecision {
        logger.record("approval_request_fetch_started", requestID: nil)
        let request = try client.fetchPendingRequest()
        logger.record("approval_request_loaded", requestID: request.requestID)

        let decisionKind = presenter.decide(for: request)
        let reusableUses = decisionKind == .approveReusable ? 3 : nil
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
}

public final class StaticDecisionPresenter: ApprovalPresenter {
    private let decision: ApprovalDecisionKind

    public init(decision: ApprovalDecisionKind) {
        self.decision = decision
    }

    public func decide(for _: ApprovalRequest) -> ApprovalDecisionKind {
        decision
    }
}

public final class MockDaemonClient: ApprovalDaemonClient {
    private let request: ApprovalRequest
    private(set) public var submittedDecision: ApprovalDecision?

    public init(request: ApprovalRequest) {
        self.request = request
    }

    public func fetchPendingRequest() throws -> ApprovalRequest {
        request
    }

    public func submit(_ decision: ApprovalDecision) throws {
        submittedDecision = decision
    }
}
