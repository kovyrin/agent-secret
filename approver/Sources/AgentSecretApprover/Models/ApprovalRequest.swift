import Foundation

/// Approval context shown to the local operator before a command receives access.
public struct ApprovalRequest: Codable, Equatable, Sendable {
    private enum CodingKeys: String, CodingKey {
        case command
        case cwd
        case expiresAt = "expires_at"
        case nonce
        case operation
        case allowsReusable = "allows_reusable"
        case overrideEnv = "override_env"
        case overriddenAliases = "overridden_aliases"
        case reason
        case requestID = "request_id"
        case resolvedExecutable = "resolved_executable"
        case reusableUses = "reusable_uses"
        case resources
    }

    /// Default reusable approval count for programmatic requests and out-of-range daemon values.
    public static let defaultReusableUses: Int = 3
    /// Maximum reusable approval count accepted from daemon payloads.
    public static let maxReusableUses: Int = 20

    public var requestID: String
    public var nonce: String
    public var reason: String
    public var command: [String]
    public var cwd: String
    public var resolvedExecutable: String
    public var expiresAt: Date
    public var operation: ApprovalOperation
    public var allowsReusable: Bool
    public var resources: [RequestedResource]
    public var overrideEnv: Bool
    public var overriddenAliases: [String]
    public var reusableUses: Int

    init(
        requestID: String,
        nonce: String,
        reason: String,
        command: [String],
        cwd: String,
        expiresAt: Date,
        resources: [RequestedResource],
        resolvedExecutable: String,
        operation: ApprovalOperation = .exec,
        allowsReusable: Bool = true,
        overrideEnv: Bool = false,
        overriddenAliases: [String] = [],
        reusableUses: Int = Self.defaultReusableUses
    ) {
        self.requestID = requestID
        self.nonce = nonce
        self.reason = reason
        self.command = command
        self.cwd = cwd
        self.resolvedExecutable = resolvedExecutable
        self.expiresAt = expiresAt
        self.operation = operation
        self.allowsReusable = allowsReusable
        self.resources = resources
        self.overrideEnv = overrideEnv
        self.overriddenAliases = overriddenAliases
        self.reusableUses = Self.boundedReusableUses(reusableUses)
    }

    /// Decodes current daemon protocol payloads.
    public init(from decoder: Decoder) throws {
        let container: KeyedDecodingContainer<CodingKeys> = try decoder.container(keyedBy: CodingKeys.self)
        requestID = try container.decode(String.self, forKey: .requestID)
        nonce = try container.decode(String.self, forKey: .nonce)
        reason = try container.decode(String.self, forKey: .reason)
        command = try container.decode([String].self, forKey: .command)
        cwd = try container.decode(String.self, forKey: .cwd)
        resolvedExecutable = try container.decode(String.self, forKey: .resolvedExecutable)
        expiresAt = try container.decode(Date.self, forKey: .expiresAt)
        operation = try container.decode(ApprovalOperation.self, forKey: .operation)
        allowsReusable = try container.decode(Bool.self, forKey: .allowsReusable)
        resources = try container.decode([RequestedResource].self, forKey: .resources)
        overrideEnv = try container.decode(Bool.self, forKey: .overrideEnv)
        overriddenAliases = try container.decode([String].self, forKey: .overriddenAliases)
        let decodedReusableUses: Int = try container.decode(
            Int.self,
            forKey: .reusableUses
        )
        reusableUses = Self.boundedReusableUses(decodedReusableUses)
    }

    static func boundedReusableUses(_ uses: Int) -> Int {
        guard (1 ... maxReusableUses).contains(uses) else {
            return defaultReusableUses
        }
        return uses
    }
}
