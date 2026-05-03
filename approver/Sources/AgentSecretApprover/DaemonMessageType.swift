import Foundation

struct DaemonMessageType: Codable, Equatable, ExpressibleByStringLiteral, Hashable, RawRepresentable {
    static let daemonStatus = Self(rawValue: "daemon.status")
    static let daemonStop = Self(rawValue: "daemon.stop")
    static let approvalPending = Self(rawValue: "approval.pending")
    static let approvalDecision = Self(rawValue: "approval.decision")
    static let requestExec = Self(rawValue: "request.exec")
    static let commandStarted = Self(rawValue: "command.started")
    static let commandCompleted = Self(rawValue: "command.completed")
    static let okResponse = Self(rawValue: "ok")
    static let error = Self(rawValue: "error")

    let rawValue: String

    init(rawValue: String) {
        self.rawValue = rawValue
    }

    init(stringLiteral value: String) {
        self.init(rawValue: value)
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        rawValue = try container.decode(String.self)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}
