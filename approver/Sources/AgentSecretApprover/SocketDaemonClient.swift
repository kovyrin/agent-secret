import Foundation

#if canImport(Darwin)
import Darwin
#endif

public enum SocketDaemonClientError: Error, CustomStringConvertible, Equatable {
    case pathTooLong(String)
    case socketUnavailable
    case connectFailed(Int32)
    case readFailed(Int32)
    case writeFailed(Int32)
    case disconnected
    case daemonError(String, String)
    case invalidResponse(String)

    public var description: String {
        switch self {
        case let .pathTooLong(path):
            "socket path is too long: \(path)"
        case .socketUnavailable:
            "unix sockets are unavailable on this platform"
        case let .connectFailed(errnoValue):
            "connect failed: errno \(errnoValue)"
        case let .readFailed(errnoValue):
            "read failed: errno \(errnoValue)"
        case let .writeFailed(errnoValue):
            "write failed: errno \(errnoValue)"
        case .disconnected:
            "daemon disconnected"
        case let .daemonError(code, message):
            "daemon error \(code): \(message)"
        case let .invalidResponse(message):
            "invalid daemon response: \(message)"
        }
    }
}

public final class SocketDaemonClient: ApprovalDaemonClient {
    private let transport: LineTransport
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder

    public convenience init(socketPath: String) throws {
        try self.init(transport: UnixSocketLineTransport(path: socketPath))
    }

    init(transport: LineTransport) {
        self.transport = transport
        decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom(AgentSecretDateCoding.decode)
        encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
    }

    public func fetchPendingRequest() throws -> ApprovalRequest {
        let request = DaemonEnvelope<EmptyPayload>(
            version: 1,
            type: "approval.pending",
            requestID: nil,
            nonce: nil,
            payload: nil
        )
        try send(request)
        let data = try transport.readLine()
        let header = try decoder.decode(DaemonHeader.self, from: data)
        if header.type == "error" {
            throw try daemonError(from: data)
        }
        guard header.type == "ok" else {
            throw SocketDaemonClientError.invalidResponse("unexpected response type \(header.type)")
        }
        let response = try decoder.decode(DaemonEnvelope<ApprovalRequest>.self, from: data)
        guard let payload = response.payload else {
            throw SocketDaemonClientError.invalidResponse("missing approval request payload")
        }
        return payload
    }

    public func submit(_ decision: ApprovalDecision) throws {
        let request = DaemonEnvelope(
            version: 1,
            type: "approval.decision",
            requestID: decision.requestID,
            nonce: decision.nonce,
            payload: decision
        )
        try send(request)
        let data = try transport.readLine()
        let header = try decoder.decode(DaemonHeader.self, from: data)
        if header.type == "error" {
            throw try daemonError(from: data)
        }
        guard header.type == "ok" else {
            throw SocketDaemonClientError.invalidResponse("unexpected response type \(header.type)")
        }
    }

    private func send<Payload: Encodable>(_ envelope: DaemonEnvelope<Payload>) throws {
        let data = try encoder.encode(envelope)
        try transport.writeLine(data)
    }

    private func daemonError(from data: Data) throws -> SocketDaemonClientError {
        let response = try decoder.decode(DaemonEnvelope<DaemonErrorPayload>.self, from: data)
        let payload = response.payload
        return .daemonError(payload?.code ?? "unknown", payload?.message ?? "unknown daemon error")
    }
}

struct DaemonEnvelope<Payload: Codable>: Codable {
    var version: Int
    var type: String
    var requestID: String?
    var nonce: String?
    var payload: Payload?

    private enum CodingKeys: String, CodingKey {
        case version
        case type
        case requestID = "request_id"
        case nonce
        case payload
    }
}

struct DaemonHeader: Decodable {
    var version: Int
    var type: String
}

struct DaemonErrorPayload: Codable {
    var code: String
    var message: String
}

struct EmptyPayload: Codable {}

private enum AgentSecretDateCoding {
    static func decode(from decoder: Decoder) throws -> Date {
        let container = try decoder.singleValueContainer()
        let value = try container.decode(String.self)
        let fractionalFormatter = ISO8601DateFormatter()
        fractionalFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let plainFormatter = ISO8601DateFormatter()

        for formatter in [fractionalFormatter, plainFormatter] {
            if let date = formatter.date(from: value) {
                return date
            }
        }

        throw DecodingError.dataCorruptedError(
            in: container,
            debugDescription: "invalid ISO8601 date: \(value)"
        )
    }
}

protocol LineTransport {
    func writeLine(_ data: Data) throws
    func readLine() throws -> Data
}

#if canImport(Darwin)
final class UnixSocketLineTransport: LineTransport {
    private let fd: Int32

    init(path: String) throws {
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw SocketDaemonClientError.connectFailed(errno)
        }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        var pathBytes = Array(path.utf8)
        pathBytes.append(0)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard pathBytes.count <= capacity else {
            close(fd)
            throw SocketDaemonClientError.pathTooLong(path)
        }
        withUnsafeMutableBytes(of: &address.sun_path) { rawBuffer in
            rawBuffer.copyBytes(from: pathBytes)
        }

        let status = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                connect(fd, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard status == 0 else {
            let errnoValue = errno
            close(fd)
            throw SocketDaemonClientError.connectFailed(errnoValue)
        }
    }

    deinit {
        close(fd)
    }

    func writeLine(_ data: Data) throws {
        var bytes = Array(data)
        bytes.append(10)
        var written = 0
        while written < bytes.count {
            let count = bytes.withUnsafeBytes { rawBuffer in
                Darwin.write(
                    fd,
                    rawBuffer.baseAddress!.advanced(by: written),
                    bytes.count - written
                )
            }
            guard count > 0 else {
                throw SocketDaemonClientError.writeFailed(errno)
            }
            written += count
        }
    }

    func readLine() throws -> Data {
        var output = Data()
        var byte: UInt8 = 0
        while true {
            let count = Darwin.read(fd, &byte, 1)
            if count == 0 {
                throw SocketDaemonClientError.disconnected
            }
            guard count > 0 else {
                throw SocketDaemonClientError.readFailed(errno)
            }
            if byte == 10 {
                return output
            }
            output.append(byte)
        }
    }
}
#else
final class UnixSocketLineTransport: LineTransport {
    init(path _: String) throws {
        throw SocketDaemonClientError.socketUnavailable
    }

    func writeLine(_: Data) throws {
        throw SocketDaemonClientError.socketUnavailable
    }

    func readLine() throws -> Data {
        throw SocketDaemonClientError.socketUnavailable
    }
}
#endif
