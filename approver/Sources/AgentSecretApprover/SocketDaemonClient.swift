import Foundation

/// Daemon client that exchanges newline-delimited JSON over a Unix socket.
public final class SocketDaemonClient: ApprovalDaemonClient {
    private enum AgentSecretDateCoding {
        static func decode(from decoder: Decoder) throws -> Date {
            let container: SingleValueDecodingContainer = try decoder.singleValueContainer()
            let value: String = try container.decode(String.self)
            let fractionalFormatter = ISO8601DateFormatter()
            fractionalFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            let plainFormatter = ISO8601DateFormatter()

            for formatter in [fractionalFormatter, plainFormatter] {
                if let date: Date = formatter.date(from: value) {
                    return date
                }
            }

            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "invalid ISO8601 date: \(value)"
            )
        }
    }

    private static let protocolVersion: Int = 1
    private static let typeError: String = "error"
    private static let typeOK: String = "ok"

    private let transport: LineTransport
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder

    /// Creates a daemon client connected to a Unix socket path.
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

    /// Fetches the pending approval request from the daemon.
    public func fetchPendingRequest() throws -> ApprovalRequest {
        let request = DaemonEnvelope<EmptyPayload>(
            nonce: nil,
            payload: nil,
            requestID: nil,
            type: "approval.pending",
            version: Self.protocolVersion
        )
        try send(request)
        let response: DaemonEnvelope<ApprovalRequest> = try readOKEnvelope()
        guard let payload: ApprovalRequest = response.payload else {
            throw SocketDaemonClientError.invalidResponse("missing approval request payload")
        }
        try validateCorrelation(
            response,
            requestID: payload.requestID,
            nonce: payload.nonce
        )
        return payload
    }

    /// Submits an approval decision to the daemon.
    public func submit(_ decision: ApprovalDecision) throws {
        let request = DaemonEnvelope<ApprovalDecision>(
            nonce: decision.nonce,
            payload: decision,
            requestID: decision.requestID,
            type: "approval.decision",
            version: Self.protocolVersion
        )
        try send(request)
        let response: DaemonEnvelope<EmptyPayload> = try readOKEnvelope()
        try validateCorrelation(
            response,
            requestID: decision.requestID,
            nonce: decision.nonce
        )
    }

    private func readOKEnvelope<Payload: Codable>() throws -> DaemonEnvelope<Payload> {
        let data: Data = try transport.readLine()
        let header: DaemonHeader = try decoder.decode(DaemonHeader.self, from: data)
        try validateHeader(header)
        if header.type == Self.typeError {
            throw try daemonError(from: data)
        }
        guard header.type == Self.typeOK else {
            throw SocketDaemonClientError.invalidResponse("unexpected response type \(header.type)")
        }
        return try decoder.decode(DaemonEnvelope<Payload>.self, from: data)
    }

    private func validateHeader(_ header: DaemonHeader) throws {
        guard header.version == Self.protocolVersion else {
            throw SocketDaemonClientError.invalidResponse(
                "unsupported protocol version \(header.version)"
            )
        }
    }

    private func validateCorrelation(
        _ response: DaemonEnvelope<some Codable>,
        requestID: String,
        nonce: String
    ) throws {
        guard response.requestID == requestID else {
            throw SocketDaemonClientError.invalidResponse("response request id mismatch")
        }
        guard response.nonce == nonce else {
            throw SocketDaemonClientError.invalidResponse("response nonce mismatch")
        }
    }

    private func daemonError(from data: Data) throws -> SocketDaemonClientError {
        let response: DaemonEnvelope<DaemonErrorPayload> = try decoder.decode(
            DaemonEnvelope<DaemonErrorPayload>.self,
            from: data
        )
        let payload: DaemonErrorPayload? = response.payload
        let code: String = DaemonErrorDisplay.sanitizedCode(payload?.code)
        return .daemonError(code, DaemonErrorDisplay.message(for: code))
    }

    private func send(_ envelope: DaemonEnvelope<some Encodable>) throws {
        let data: Data = try encoder.encode(envelope)
        try transport.writeLine(data)
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
