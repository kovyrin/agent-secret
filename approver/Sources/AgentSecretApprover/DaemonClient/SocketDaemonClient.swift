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
                debugDescription: "invalid ISO8601 date"
            )
        }
    }

    private static let protocolVersion: Int = 1

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

    public func fetchPendingRequest() throws -> ApprovalRequest {
        let request = DaemonEnvelope<EmptyPayload>(
            nonce: nil,
            payload: nil,
            requestID: nil,
            type: .approvalPending,
            version: Self.protocolVersion
        )
        try send(request)
        let response: DaemonPayloadEnvelope<ApprovalRequest> = try readOKPayloadEnvelope()
        let payload: ApprovalRequest = response.payload
        try validateCorrelation(
            response,
            requestID: payload.requestID,
            nonce: payload.nonce
        )
        return payload
    }

    public func submit(_ decision: ApprovalDecision) throws {
        let request = DaemonEnvelope<ApprovalDecision>(
            nonce: decision.nonce,
            payload: decision,
            requestID: decision.requestID,
            type: .approvalDecision,
            version: Self.protocolVersion
        )
        try send(request)
        try readOKAck(
            requestID: decision.requestID,
            nonce: decision.nonce
        )
    }

    private func readOKPayloadEnvelope<Payload: Codable>(
        requestID: String? = nil,
        nonce: String? = nil
    ) throws -> DaemonPayloadEnvelope<Payload> {
        let data: Data = try readOKData(requestID: requestID, nonce: nonce)
        let response: DaemonPayloadEnvelope<Payload> = try decodeEnvelope(
            DaemonPayloadEnvelope<Payload>.self,
            from: data,
            invalidMessage: "malformed daemon response payload"
        )
        try validateCorrelationIfNeeded(response, requestID: requestID, nonce: nonce)
        return response
    }

    private func readOKAck(requestID: String, nonce: String) throws {
        let data: Data = try readOKData(requestID: requestID, nonce: nonce)
        let response: DaemonEnvelope<EmptyPayload> = try decodeEnvelope(
            DaemonEnvelope<EmptyPayload>.self,
            from: data,
            invalidMessage: "malformed daemon response payload"
        )
        try validateCorrelation(response, requestID: requestID, nonce: nonce)
    }

    private func readOKData(requestID: String? = nil, nonce: String? = nil) throws -> Data {
        let data: Data = try transport.readLine()
        let header: DaemonHeader = try decodeHeader(from: data)
        try validateHeader(header)
        if header.type == .error {
            let response: DaemonPayloadEnvelope<DaemonErrorPayload> = try decodeEnvelope(
                DaemonPayloadEnvelope<DaemonErrorPayload>.self,
                from: data,
                invalidMessage: "malformed daemon error response"
            )
            try validateCorrelationIfNeeded(response, requestID: requestID, nonce: nonce)
            throw daemonError(from: response.payload)
        }
        guard header.type == .okResponse else {
            throw SocketDaemonClientError.invalidResponse("unexpected response type")
        }
        return data
    }

    private func decodeHeader(from data: Data) throws -> DaemonHeader {
        do {
            return try decoder.decode(DaemonHeader.self, from: data)
        } catch {
            throw SocketDaemonClientError.malformedResponse(
                "malformed daemon response header",
                underlying: error
            )
        }
    }

    private func decodeEnvelope<Envelope: Codable>(
        _ type: Envelope.Type,
        from data: Data,
        invalidMessage: String
    ) throws -> Envelope {
        do {
            return try decoder.decode(type, from: data)
        } catch {
            throw SocketDaemonClientError.malformedResponse(invalidMessage, underlying: error)
        }
    }

    private func validateHeader(_ header: DaemonHeader) throws {
        guard header.version == Self.protocolVersion else {
            throw SocketDaemonClientError.invalidResponse(
                "unsupported protocol version \(header.version)"
            )
        }
    }

    private func validateCorrelation(
        _ response: some DaemonEnvelopeMetadata,
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

    private func validateCorrelationIfNeeded(
        _ response: some DaemonEnvelopeMetadata,
        requestID: String?,
        nonce: String?
    ) throws {
        guard let requestID, let nonce else {
            return
        }
        try validateCorrelation(response, requestID: requestID, nonce: nonce)
    }

    private func daemonError(from payload: DaemonErrorPayload) -> SocketDaemonClientError {
        .daemonError(payload.code)
    }

    private func send(_ envelope: DaemonEnvelope<some Encodable>) throws {
        let data: Data = try encoder.encode(envelope)
        try transport.writeLine(data)
    }
}
