import Foundation

/// Presenter-level decision metadata before request-expiration policy is applied.
public struct ApprovalPresentationDecision: Equatable, Sendable {
    public let kind: ApprovalDecisionKind
    public let denialReason: ApprovalDenialReason?

    public init(kind: ApprovalDecisionKind, denialReason: ApprovalDenialReason? = nil) {
        self.kind = kind
        self.denialReason = kind == .deny ? denialReason : nil
    }
}
