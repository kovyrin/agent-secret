import Foundation

/// Decision payload submitted from the approver back to the daemon.
public struct ApprovalDecision: Codable, Equatable, Sendable {
    private enum CodingKeys: String, CodingKey {
        case requestID
        case nonce
        case decision
        case reusableUses
    }

    public let requestID: String
    public let nonce: String
    public let decision: ApprovalDecisionKind
    public let reusableUses: Int?

    private init(
        requestID: String,
        nonce: String,
        decision: ApprovalDecisionKind,
        reusableUses: Int?
    ) {
        self.requestID = requestID
        self.nonce = nonce
        self.decision = decision
        self.reusableUses = reusableUses
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let requestID = try container.decode(String.self, forKey: .requestID)
        let nonce = try container.decode(String.self, forKey: .nonce)
        let decision = try container.decode(ApprovalDecisionKind.self, forKey: .decision)
        let reusableUses = try container.decodeIfPresent(Int.self, forKey: .reusableUses)
        try Self.validate(decision: decision, reusableUses: reusableUses, in: container)
        self.init(
            requestID: requestID,
            nonce: nonce,
            decision: decision,
            reusableUses: reusableUses
        )
    }

    /// Creates a one-time approval response.
    public static func approveOnce(requestID: String, nonce: String) -> Self {
        Self(requestID: requestID, nonce: nonce, decision: .approveOnce, reusableUses: nil)
    }

    /// Creates a reusable approval response with the daemon-provided use limit.
    public static func approveReusable(requestID: String, nonce: String, reusableUses: Int) -> Self {
        Self(
            requestID: requestID,
            nonce: nonce,
            decision: .approveReusable,
            reusableUses: reusableUses
        )
    }

    /// Creates a denial response.
    public static func deny(requestID: String, nonce: String) -> Self {
        Self(requestID: requestID, nonce: nonce, decision: .deny, reusableUses: nil)
    }

    /// Creates a timeout response.
    public static func timeout(requestID: String, nonce: String) -> Self {
        Self(requestID: requestID, nonce: nonce, decision: .timeout, reusableUses: nil)
    }

    private static func validate(
        decision: ApprovalDecisionKind,
        reusableUses: Int?,
        in container: KeyedDecodingContainer<CodingKeys>
    ) throws {
        switch decision {
        case .approveReusable:
            guard reusableUses != nil else {
                throw DecodingError.dataCorruptedError(
                    forKey: .reusableUses,
                    in: container,
                    debugDescription: "approve_reusable decisions require reusableUses"
                )
            }

        case .approveOnce, .deny, .timeout:
            guard reusableUses == nil else {
                throw DecodingError.dataCorruptedError(
                    forKey: .reusableUses,
                    in: container,
                    debugDescription: "\(decision.rawValue) decisions must not include reusableUses"
                )
            }
        }
    }
}
