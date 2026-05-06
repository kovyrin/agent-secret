import Foundation

/// Encodes only daemon decision metadata; reusable use limits are normalized before submission.
public struct ApprovalDecision: Codable, Equatable, Sendable {
    private enum CodingKeys: String, CodingKey {
        case requestID = "request_id"
        case nonce
        case decision
        case reusableUses = "reusable_uses"
        case denialReason = "denial_reason"
    }

    public let requestID: String
    public let nonce: String
    public let decision: ApprovalDecisionKind
    public let reusableUses: Int?
    public let denialReason: ApprovalDenialReason?

    private init(
        requestID: String,
        nonce: String,
        decision: ApprovalDecisionKind,
        reusableUses: Int?,
        denialReason: ApprovalDenialReason?
    ) {
        self.requestID = requestID
        self.nonce = nonce
        self.decision = decision
        self.reusableUses = reusableUses
        self.denialReason = denialReason
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let requestID = try container.decode(String.self, forKey: .requestID)
        let nonce = try container.decode(String.self, forKey: .nonce)
        let decision = try container.decode(ApprovalDecisionKind.self, forKey: .decision)
        let reusableUses = try Self.normalizedReusableUses(
            decision: decision,
            reusableUses: container.decodeIfPresent(Int.self, forKey: .reusableUses),
            in: container
        )
        let denialReason = try Self.normalizedDenialReason(
            decision: decision,
            denialReason: container.decodeIfPresent(ApprovalDenialReason.self, forKey: .denialReason),
            in: container
        )
        self.init(
            requestID: requestID,
            nonce: nonce,
            decision: decision,
            reusableUses: reusableUses,
            denialReason: denialReason
        )
    }

    public static func approveOnce(for request: ApprovalRequest) -> Self {
        Self(
            requestID: request.requestID,
            nonce: request.nonce,
            decision: .approveOnce,
            reusableUses: nil,
            denialReason: nil
        )
    }

    public static func approveReusable(for request: ApprovalRequest) -> Self {
        Self(
            requestID: request.requestID,
            nonce: request.nonce,
            decision: .approveReusable,
            reusableUses: request.reusableUses,
            denialReason: nil
        )
    }

    public static func deny(
        for request: ApprovalRequest,
        reason: ApprovalDenialReason? = nil
    ) -> Self {
        Self(
            requestID: request.requestID,
            nonce: request.nonce,
            decision: .deny,
            reusableUses: nil,
            denialReason: reason
        )
    }

    public static func timeout(for request: ApprovalRequest) -> Self {
        Self(
            requestID: request.requestID,
            nonce: request.nonce,
            decision: .timeout,
            reusableUses: nil,
            denialReason: nil
        )
    }

    private static func normalizedReusableUses(
        decision: ApprovalDecisionKind,
        reusableUses: Int?,
        in container: KeyedDecodingContainer<CodingKeys>
    ) throws -> Int? {
        switch decision {
        case .approveReusable:
            guard let reusableUses else {
                throw DecodingError.dataCorruptedError(
                    forKey: .reusableUses,
                    in: container,
                    debugDescription: "approve_reusable decisions require reusableUses"
                )
            }
            return ApprovalRequest.boundedReusableUses(reusableUses)

        case .approveOnce, .deny, .timeout:
            guard reusableUses == nil else {
                throw DecodingError.dataCorruptedError(
                    forKey: .reusableUses,
                    in: container,
                    debugDescription: "\(decision.rawValue) decisions must not include reusableUses"
                )
            }
            return nil
        }
    }

    private static func normalizedDenialReason(
        decision: ApprovalDecisionKind,
        denialReason: ApprovalDenialReason?,
        in container: KeyedDecodingContainer<CodingKeys>
    ) throws -> ApprovalDenialReason? {
        switch decision {
        case .deny:
            return denialReason

        case .approveOnce, .approveReusable, .timeout:
            guard denialReason == nil else {
                throw DecodingError.dataCorruptedError(
                    forKey: .denialReason,
                    in: container,
                    debugDescription: "\(decision.rawValue) decisions must not include denialReason"
                )
            }
            return nil
        }
    }
}
