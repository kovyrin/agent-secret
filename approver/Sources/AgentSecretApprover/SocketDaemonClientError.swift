import Foundation

/// Errors returned while talking to the local daemon socket.
public enum SocketDaemonClientError: Error, CustomStringConvertible, Equatable {
    /// The socket connect syscall failed.
    case connectFailed(Int32)
    /// The daemon returned a structured error response.
    case daemonError(String, String)
    /// The daemon closed the connection before a full line arrived.
    case disconnected
    /// The daemon socket line exceeded the configured frame limit.
    case frameTooLarge(Int)
    /// The daemon returned an unexpected response shape.
    case invalidResponse(String)
    /// The socket path does not fit in a Unix socket address.
    case pathTooLong(String)
    /// The socket read syscall failed.
    case readFailed(Int32)
    /// The daemon did not send a complete response before the read timeout.
    case readTimedOut
    /// Unix sockets are unavailable on this platform.
    case socketUnavailable
    /// The socket write syscall failed.
    case writeFailed(Int32)
    /// The daemon did not accept the request before the write timeout.
    case writeTimedOut

    /// Human-readable error message for CLI output.
    public var description: String {
        switch self {
        case let .connectFailed(errnoValue):
            "connect failed: errno \(errnoValue)"

        case let .daemonError(code, _):
            "daemon error \(DaemonErrorDisplay.sanitizedCode(code)): \(DaemonErrorDisplay.message(for: code))"

        case .disconnected:
            "daemon disconnected"

        case let .frameTooLarge(maxBytes):
            "daemon frame exceeds maximum size of \(maxBytes) bytes"

        case let .invalidResponse(message):
            "invalid daemon response: \(message)"

        case let .pathTooLong(path):
            "socket path is too long: \(path)"

        case let .readFailed(errnoValue):
            "read failed: errno \(errnoValue)"

        case .readTimedOut:
            "read timed out waiting for daemon response"

        case .socketUnavailable:
            "unix sockets are unavailable on this platform"

        case let .writeFailed(errnoValue):
            "write failed: errno \(errnoValue)"

        case .writeTimedOut:
            "write timed out sending daemon request"
        }
    }
}
