import Foundation

enum DaemonMessageType: String, Codable, Equatable, Hashable {
    case approvalDecision = "approval.decision"
    case approvalPending = "approval.pending"
    case commandCompleted = "command.completed"
    case commandStarted = "command.started"
    case daemonStatus = "daemon.status"
    case daemonStop = "daemon.stop"
    case error
    case okResponse = "ok"
    case requestExec = "request.exec"
    case unknown

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let rawValue = try container.decode(String.self)
        self = Self(rawValue: rawValue) ?? .unknown
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}
