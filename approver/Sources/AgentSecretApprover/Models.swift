import Foundation

public struct ApprovalRequest: Codable, Equatable, Sendable {
    public var requestID: String
    public var nonce: String
    public var reason: String
    public var command: [String]
    public var cwd: String
    public var resolvedExecutable: String?
    public var expiresAt: Date
    public var secrets: [RequestedSecret]
    public var overrideEnv: Bool
    public var overriddenAliases: [String]
    public var reusableUses: Int

    public init(
        requestID: String,
        nonce: String,
        reason: String,
        command: [String],
        cwd: String,
        resolvedExecutable: String? = nil,
        expiresAt: Date,
        secrets: [RequestedSecret],
        overrideEnv: Bool = false,
        overriddenAliases: [String] = [],
        reusableUses: Int = 3
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
        self.overriddenAliases = overriddenAliases
        self.reusableUses = reusableUses
    }

    private enum CodingKeys: String, CodingKey {
        case requestID
        case nonce
        case reason
        case command
        case cwd
        case resolvedExecutable
        case expiresAt
        case secrets
        case overrideEnv
        case overriddenAliases
        case reusableUses
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        requestID = try container.decode(String.self, forKey: .requestID)
        nonce = try container.decode(String.self, forKey: .nonce)
        reason = try container.decode(String.self, forKey: .reason)
        command = try container.decode([String].self, forKey: .command)
        cwd = try container.decode(String.self, forKey: .cwd)
        resolvedExecutable = try container.decodeIfPresent(String.self, forKey: .resolvedExecutable)
        expiresAt = try container.decode(Date.self, forKey: .expiresAt)
        secrets = try container.decode([RequestedSecret].self, forKey: .secrets)
        overrideEnv = try container.decodeIfPresent(Bool.self, forKey: .overrideEnv) ?? false
        overriddenAliases = try container.decodeIfPresent([String].self, forKey: .overriddenAliases) ?? []
        reusableUses = try container.decodeIfPresent(Int.self, forKey: .reusableUses) ?? 3
    }
}

public struct RequestedSecret: Codable, Equatable, Sendable {
    public var alias: String
    public var ref: String

    public init(alias: String, ref: String) {
        self.alias = alias
        self.ref = ref
    }
}

public enum ApprovalDecisionKind: String, Codable, Equatable, Sendable {
    case approveOnce = "approve_once"
    case approveReusable = "approve_reusable"
    case deny
    case timeout
}

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

public struct ApprovalRequestViewModel: Equatable, Sendable {
    public let title: String
    public let reason: String
    public let command: String
    public let cwd: String
    public let resolvedExecutable: String?
    public let secretRows: [String]
    public let timeRemaining: String
    public let allowReusableTitle: String
    public let overrideWarning: String?
    public let renderedText: String

    public init(request: ApprovalRequest, now: Date = Date()) {
        title = "Approve an agent-secret request"
        reason = request.reason
        command = request.command.joined(separator: " ")
        cwd = request.cwd
        resolvedExecutable = request.resolvedExecutable
        secretRows = request.secrets.map { "\($0.alias) -> \($0.ref)" }
        timeRemaining = Self.formatRemaining(request.expiresAt.timeIntervalSince(now))
        allowReusableTitle = "Allow same command for \(timeRemaining) / \(request.reusableUses) uses"
        if request.overrideEnv, !request.overriddenAliases.isEmpty {
            overrideWarning = "Will replace existing variables: \(request.overriddenAliases.joined(separator: ", "))"
        } else {
            overrideWarning = nil
        }

        var lines = [
            title,
            "Reason: \(reason)",
            "Command: \(command)",
            "Working directory: \(cwd)"
        ]
        if let resolvedExecutable, !resolvedExecutable.isEmpty {
            lines.append("Resolved binary: \(resolvedExecutable)")
        }
        lines.append("Secrets:")
        lines.append(contentsOf: secretRows)
        lines.append("Time remaining: \(timeRemaining)")
        lines.append("Reusable approval keeps values in daemon memory for this window and is limited to \(request.reusableUses) uses.")
        if let overrideWarning {
            lines.append(overrideWarning)
        }
        renderedText = lines.joined(separator: "\n")
    }

    private static func formatRemaining(_ interval: TimeInterval) -> String {
        let seconds = max(0, Int(interval.rounded(.down)))
        if seconds >= 60 {
            let minutes = seconds / 60
            let remainingSeconds = seconds % 60
            return remainingSeconds == 0 ? "\(minutes)m" : "\(minutes)m \(remainingSeconds)s"
        }
        return "\(seconds)s"
    }
}
