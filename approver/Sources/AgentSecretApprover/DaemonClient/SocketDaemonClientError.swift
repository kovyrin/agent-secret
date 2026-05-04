import Foundation

enum SocketDaemonClientError: Error, CustomStringConvertible, Equatable {
    case connectFailed(Int32)
    case daemonError(DaemonErrorCode)
    case disconnected
    case frameTooLarge(Int)
    case invalidResponse(String)
    case malformedResponse(String, underlying: Error)
    case pathTooLong(String)
    case readFailed(Int32)
    case readTimedOut
    case socketUnavailable
    case untrustedDaemon(String)
    case writeFailed(Int32)
    case writeTimedOut

    var description: String {
        switch self {
        case let .connectFailed(errnoValue):
            "connect failed: errno \(errnoValue)"

        case let .daemonError(code):
            Self.daemonErrorDescription(code: code)

        case .disconnected:
            "daemon disconnected"

        case let .frameTooLarge(maxBytes):
            "daemon frame exceeds maximum size of \(maxBytes) bytes"

        case let .invalidResponse(message):
            "invalid daemon response: \(message)"

        case let .malformedResponse(message, _):
            "invalid daemon response: \(message)"

        case let .pathTooLong(path):
            "socket path is too long: \(path)"

        case let .readFailed(errnoValue):
            "read failed: errno \(errnoValue)"

        case .readTimedOut:
            "read timed out waiting for daemon response"

        case .socketUnavailable:
            "unix sockets are unavailable on this platform"

        case let .untrustedDaemon(message):
            "untrusted daemon peer: \(message)"

        case let .writeFailed(errnoValue):
            "write failed: errno \(errnoValue)"

        case .writeTimedOut:
            "write timed out sending daemon request"
        }
    }

    private static func daemonErrorDescription(code: DaemonErrorCode) -> String {
        let displayCode = DaemonErrorDisplay.displayCode(code).rawValue
        return "daemon error \(displayCode): \(DaemonErrorDisplay.message(for: code))"
    }

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.description == rhs.description
    }
}
