@testable import AgentSecretApprover
import Foundation
import XCTest

final class SocketDaemonClientPayloadEnvelopeTests: XCTestCase {
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
            /* Test responses do not inspect outbound requests. */
        }
    }

    private static let expectedProtocolVersion: Int = 1
    private static let requestID: String = "req_123"
    private static let responseOK: DaemonMessageType = .okResponse
    private static let sampleNonce: String = "nonce_456"

    private static func approvalResponseWithoutPayload() throws -> Data {
        try encode(
            DaemonEnvelope<EmptyPayload>(
                nonce: sampleNonce,
                payload: nil,
                requestID: requestID,
                type: responseOK,
                version: expectedProtocolVersion
            )
        )
    }

    private static func errorResponseWithoutPayload() throws -> Data {
        try encode(
            DaemonEnvelope<EmptyPayload>(
                nonce: nil,
                payload: nil,
                requestID: nil,
                type: .error,
                version: expectedProtocolVersion
            )
        )
    }

    private static func encode(_ envelope: DaemonEnvelope<EmptyPayload>) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(envelope)
    }

    private func assertMalformedResponse(
        _ expected: String,
        _ expression: () throws -> Void
    ) {
        XCTAssertThrowsError(try expression()) { error in
            guard case let .malformedResponse(message, underlying) = error as? SocketDaemonClientError else {
                XCTFail("error = \(error), want malformed response")
                return
            }
            XCTAssertEqual(message, expected)
            XCTAssertTrue(underlying is DecodingError)
        }
    }

    func testFetchRejectsOKResponseWithoutRequiredPayload() throws {
        let client = try SocketDaemonClient(
            transport: MemoryLineTransport(reads: [Self.approvalResponseWithoutPayload()])
        )

        assertMalformedResponse("malformed daemon response payload") {
            _ = try client.fetchPendingRequest()
        }
    }

    func testRejectsDaemonErrorWithoutPayload() throws {
        let client = try SocketDaemonClient(
            transport: MemoryLineTransport(reads: [Self.errorResponseWithoutPayload()])
        )

        assertMalformedResponse("malformed daemon error response") {
            _ = try client.fetchPendingRequest()
        }
    }
}
