import Foundation

/// Decision payload submitted from the approver back to the daemon.
public struct ApprovalDecision: Codable, Equatable, Sendable {
    public var requestID: String
    public var nonce: String
    public var decision: ApprovalDecisionKind
    public var reusableUses: Int?

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
