import Foundation

/// Secret approval context shown to the local operator before a command runs.
public struct ApprovalRequest: Codable, Equatable, Sendable {
    private enum CodingKeys: String, CodingKey {
        case command
        case cwd
        case expiresAt
        case nonce
        case allowMutableExecutable
        case overrideEnv
        case overriddenAliases
        case reason
        case requestID
        case resolvedExecutable
        case reusableUses
        case secrets
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
    public var resolvedExecutable: String?
    public var expiresAt: Date
    public var secrets: [RequestedSecret]
    public var overrideEnv: Bool
    public var allowMutableExecutable: Bool
    public var overriddenAliases: [String]
    public var reusableUses: Int

    init(
        requestID: String,
        nonce: String,
        reason: String,
        command: [String],
        cwd: String,
        expiresAt: Date,
        secrets: [RequestedSecret],
        resolvedExecutable: String? = nil,
        overrideEnv: Bool = false,
        allowMutableExecutable: Bool = false,
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
        self.secrets = secrets
        self.overrideEnv = overrideEnv
        self.allowMutableExecutable = allowMutableExecutable
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
        resolvedExecutable = try container.decodeIfPresent(String.self, forKey: .resolvedExecutable)
        expiresAt = try container.decode(Date.self, forKey: .expiresAt)
        secrets = try container.decode([RequestedSecret].self, forKey: .secrets)
        overrideEnv = try container.decode(Bool.self, forKey: .overrideEnv)
        allowMutableExecutable = try container.decode(Bool.self, forKey: .allowMutableExecutable)
        overriddenAliases = try container.decode([String].self, forKey: .overriddenAliases)
        let decodedReusableUses: Int = try container.decode(
            Int.self,
            forKey: .reusableUses
        )
        reusableUses = Self.boundedReusableUses(decodedReusableUses)
    }

    private static func boundedReusableUses(_ uses: Int) -> Int {
        guard (1 ... maxReusableUses).contains(uses) else {
            return defaultReusableUses
        }
        return uses
    }
}
