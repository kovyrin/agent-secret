@testable import AgentSecretApprover
import Foundation
import XCTest

final class SocketDaemonClientErrorCorrelationTests: XCTestCase {
    private final class MemoryLineTransport: LineTransport {
        private var reads: [Data]

        init(reads: [Data]) {
            self.reads = reads
        }

        func readLine() throws -> Data {
            guard !reads.isEmpty else {
                throw SocketDaemonClientError.disconnected
            }
            return reads.removeFirst()
        }

        func writeLine(_: Data) {
            /* This test transport only needs to satisfy request writes. */
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }

    private static let expectedProtocolVersion: Int = 1
    private static let requestID: String = "req_123"
    private static let staleNonce: String = "nonce_stale"
    private static let staleRequestID: String = "req_stale"

    private static var sampleDecision: ApprovalDecision {
        ApprovalDecision(
            requestID: requestID,
            nonce: "nonce_456",
            decision: .approveOnce
        )
    }

    private static func errorResponse(
        requestID: String?,
        nonce: String?
    ) throws -> Data {
        try encode(
            DaemonEnvelope(
                nonce: nonce,
                payload: DaemonErrorPayload(
                    code: "stale_approval",
                    message: "stale approval response"
                ),
                requestID: requestID,
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

    func testSubmitRejectsMismatchedErrorResponseRequestID() throws {
        let client = try SocketDaemonClient(
            transport: MemoryLineTransport(
                reads: [
                    Self.errorResponse(
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

    func testSubmitRejectsMismatchedErrorResponseNonce() throws {
        let client = try SocketDaemonClient(
            transport: MemoryLineTransport(
                reads: [
                    Self.errorResponse(
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

    func testFetchReportsUncorrelatedDaemonErrors() throws {
        let client = try SocketDaemonClient(
            transport: MemoryLineTransport(
                reads: [
                    Self.errorResponse(
                        requestID: Self.staleRequestID,
                        nonce: Self.staleNonce
                    )
                ]
            )
        )

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
