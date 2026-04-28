import Foundation

/// Decision payload submitted from the approver back to the daemon.
public struct ApprovalDecision: Codable, Equatable, Sendable {
    /// Request identifier copied from the approval request.
    public var requestID: String
    /// Request nonce copied from the approval request.
    public var nonce: String
    /// Operator decision.
    public var decision: ApprovalDecisionKind
    /// Optional reusable approval launch limit.
    public var reusableUses: Int?

    /// Creates an approval decision payload.
    public init(
        requestID: String,
        nonce: String,
        decision: ApprovalDecisionKind,
        reusableUses: Int? = nil
    ) {
        self.requestID = requestID
        self.nonce = nonce
        self.decision = decision
        self.reusableUses = reusableUses
    }
}
