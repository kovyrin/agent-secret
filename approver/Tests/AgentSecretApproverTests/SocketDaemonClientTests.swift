@testable import AgentSecretApprover
import Foundation
import XCTest

final class SocketDaemonClientTests: XCTestCase {
    private final class MemoryLineTransport: LineTransport {
        private var reads: [Data]
        private(set) var writtenStrings: [String] = []

        init(reads: [Data]) {
            self.reads = reads
        }

        func readLine() throws -> Data {
            guard !reads.isEmpty else {
                throw SocketDaemonClientError.disconnected
            }
            return reads.removeFirst()
        }

        func writeLine(_ data: Data) {
            writtenStrings.append(String(data: data, encoding: .utf8) ?? "")
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }

    private static let expectedProtocolVersion: Int = 1
    private static let requestID: String = "req_123"
    private static let responseOK: String = "ok"
    private static let sampleExpiration: TimeInterval = 1_800_000_000
    private static let secretCanary: String = "synthetic-secret-value"
    private static let staleNonce: String = "nonce_stale"
    private static let staleRequestID: String = "req_stale"
    private static let unsupportedProtocolVersion: Int = 99

    private static var sampleDecision: ApprovalDecision {
        ApprovalDecision(
            requestID: requestID,
            nonce: "nonce_456",
            decision: .approveOnce
        )
    }

    private static var sampleRequest: ApprovalRequest {
        ApprovalRequest(
            requestID: requestID,
            nonce: "nonce_456",
            reason: "Run Terraform plan for staging",
            command: ["/opt/homebrew/bin/terraform", "plan"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: sampleExpiration),
            secrets: [
                RequestedSecret(alias: "EXAMPLE_TOKEN", ref: "op://Example Vault/Example Item/token")
            ],
            resolvedExecutable: "/opt/homebrew/bin/terraform"
        )
    }

    private static func approvalResponse(
        version: Int,
        type: String,
        envelopeRequestID: String,
        envelopeNonce: String
    ) throws -> Data {
        try encode(
            DaemonEnvelope(
                nonce: envelopeNonce,
                payload: sampleRequest,
                requestID: envelopeRequestID,
                type: type,
                version: version
            )
        )
    }

    private static func decisionResponse(
        requestID: String,
        nonce: String
    ) throws -> Data {
        try encode(
            DaemonEnvelope<EmptyPayload>(
                nonce: nonce,
                payload: nil,
                requestID: requestID,
                type: responseOK,
                version: expectedProtocolVersion
            )
        )
    }

    private static func errorResponse(
        code: String = "stale_approval",
        message: String = "stale approval response"
    ) throws -> Data {
        try encode(
            DaemonEnvelope(
                nonce: nil,
                payload: DaemonErrorPayload(code: code, message: message),
                requestID: nil,
                type: "error",
                version: expectedProtocolVersion
            )
        )
    }

    private static func encode(_ envelope: DaemonEnvelope<some Any>) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(envelope)
    }

    private func assertInvalidResponse(
        _ expected: String,
        _ expression: () throws -> Void
    ) {
        XCTAssertThrowsError(try expression()) { error in
            XCTAssertEqual(error as? SocketDaemonClientError, .invalidResponse(expected))
        }
    }

    func testFetchRejectsUnsupportedProtocolVersion() throws {
        let client = try SocketDaemonClient(
            transport: MemoryLineTransport(
                reads: [
                    Self.approvalResponse(
                        version: Self.unsupportedProtocolVersion,
                        type: Self.responseOK,
                        envelopeRequestID: Self.requestID,
                        envelopeNonce: Self.sampleDecision.nonce
                    )
                ]
            )
        )

        assertInvalidResponse("unsupported protocol version 99") {
            _ = try client.fetchPendingRequest()
        }
    }

    func testFetchRejectsUnexpectedResponseType() throws {
        let client = try SocketDaemonClient(
            transport: MemoryLineTransport(
                reads: [
                    Self.approvalResponse(
                        version: Self.expectedProtocolVersion,
                        type: "approval.pending",
                        envelopeRequestID: Self.requestID,
                        envelopeNonce: Self.sampleDecision.nonce
                    )
                ]
            )
        )

        assertInvalidResponse("unexpected response type") {
            _ = try client.fetchPendingRequest()
        }
    }

    func testFetchRejectsMismatchedResponseRequestID() throws {
        let client = try SocketDaemonClient(
            transport: MemoryLineTransport(
                reads: [
                    Self.approvalResponse(
                        version: Self.expectedProtocolVersion,
                        type: Self.responseOK,
                        envelopeRequestID: Self.staleRequestID,
                        envelopeNonce: Self.sampleDecision.nonce
                    )
                ]
            )
        )

        assertInvalidResponse("response request id mismatch") {
            _ = try client.fetchPendingRequest()
        }
    }

    func testFetchRejectsMismatchedResponseNonce() throws {
        let client = try SocketDaemonClient(
            transport: MemoryLineTransport(
                reads: [
                    Self.approvalResponse(
                        version: Self.expectedProtocolVersion,
                        type: Self.responseOK,
                        envelopeRequestID: Self.requestID,
                        envelopeNonce: Self.staleNonce
                    )
                ]
            )
        )

        assertInvalidResponse("response nonce mismatch") {
            _ = try client.fetchPendingRequest()
        }
    }

    func testSubmitRejectsMismatchedResponseRequestID() throws {
        let client = try SocketDaemonClient(
            transport: MemoryLineTransport(
                reads: [
                    Self.decisionResponse(
                        requestID: Self.staleRequestID,
                        nonce: Self.sampleDecision.nonce
                    )
                ]
            )
        )

        assertInvalidResponse("response request id mismatch") {
            try client.submit(Self.sampleDecision)
        }
    }

    func testSubmitRejectsMismatchedResponseNonce() throws {
        let client = try SocketDaemonClient(
            transport: MemoryLineTransport(
                reads: [
                    Self.decisionResponse(
                        requestID: Self.requestID,
                        nonce: Self.staleNonce
                    )
                ]
            )
        )

        assertInvalidResponse("response nonce mismatch") {
            try client.submit(Self.sampleDecision)
        }
    }

    func testFetchesAndSubmitsCorrelatedDecision() throws {
        let transport = try MemoryLineTransport(
            reads: [
                Self.approvalResponse(
                    version: Self.expectedProtocolVersion,
                    type: Self.responseOK,
                    envelopeRequestID: Self.requestID,
                    envelopeNonce: Self.sampleDecision.nonce
                ),
                Self.decisionResponse(
                    requestID: Self.requestID,
                    nonce: Self.sampleDecision.nonce
                )
            ]
        )
        let client = SocketDaemonClient(transport: transport)

        let request: ApprovalRequest = try client.fetchPendingRequest()
        XCTAssertEqual(request.requestID, Self.requestID)
        try client.submit(Self.sampleDecision)

        let written: String = transport.writtenStrings.joined(separator: "\n")
        XCTAssertTrue(written.contains("approval.pending"))
        XCTAssertTrue(written.contains("approval.decision"))
        XCTAssertFalse(written.contains(Self.secretCanary))
    }

    func testReportsDaemonErrors() throws {
        let client = try SocketDaemonClient(transport: MemoryLineTransport(reads: [Self.errorResponse()]))

        XCTAssertThrowsError(try client.fetchPendingRequest()) { error in
            XCTAssertEqual(
                error as? SocketDaemonClientError,
                .daemonError("stale_approval", "stale approval response")
            )
        }
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
