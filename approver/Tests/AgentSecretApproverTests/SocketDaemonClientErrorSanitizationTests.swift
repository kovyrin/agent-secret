@testable import AgentSecretApprover
import Foundation
import XCTest

final class SocketDaemonClientErrorSanitizationTests: XCTestCase {
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

        deinit {
            /* Required by SwiftLint. */
        }
    }

    private static let expectedProtocolVersion: Int = 1
    private static let secretCanary: String = "synthetic-secret-value"

    private static func errorResponse(code: String, message: String) throws -> Data {
        let envelope = DaemonEnvelope(
            nonce: nil,
            payload: DaemonErrorPayload(code: code, message: message),
            requestID: nil,
            type: "error",
            version: expectedProtocolVersion
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(envelope)
    }

    private static func rawResponse(type: String, expiresAt: String = "2030-01-01T00:00:00Z") throws -> Data {
        let object: [String: Any] = [
            "nonce": "nonce_456",
            "payload": [
                "command": ["/usr/bin/env", "echo"],
                "cwd": "/tmp/project",
                "expiresAt": expiresAt,
                "nonce": "nonce_456",
                "reason": "Run deployment",
                "requestID": "req_123",
                "resolvedExecutable": "/usr/bin/env",
                "secrets": [
                    [
                        "account": "prod-account-123",
                        "alias": "SECRET_ALIAS_CANARY",
                        "ref": "op://Example Vault/Deploy/token"
                    ]
                ]
            ] as [String: Any],
            "request_id": "req_123",
            "type": type,
            "version": expectedProtocolVersion
        ]
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private func assertDisplayedError(
        from expression: () throws -> Void,
        equals expected: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try expression(), file: file, line: line) { error in
            let displayed = String(describing: error)
            XCTAssertEqual(displayed, expected, file: file, line: line)
            XCTAssertFalse(displayed.contains("op://"), file: file, line: line)
            XCTAssertFalse(displayed.contains("SECRET_ALIAS_CANARY"), file: file, line: line)
            XCTAssertFalse(displayed.contains("prod-account-123"), file: file, line: line)
            XCTAssertFalse(displayed.contains(Self.secretCanary), file: file, line: line)
        }
    }

    func testDaemonErrorDisplayRedactsDaemonSuppliedMessageText() throws {
        let message = """
        failed op://Example Vault/Deploy/token for alias SECRET_ALIAS_CANARY \
        account prod-account-123 value synthetic-secret-value path /Users/alice/.ssh/id_rsa
        """
        let client = try SocketDaemonClient(
            transport: MemoryLineTransport(reads: [Self.errorResponse(code: "bad_request", message: message)])
        )

        XCTAssertThrowsError(try client.fetchPendingRequest()) { error in
            XCTAssertEqual(
                error as? SocketDaemonClientError,
                .daemonError("bad_request", "daemon rejected malformed request")
            )
            let displayed = String(describing: error)
            XCTAssertEqual(displayed, "daemon error bad_request: daemon rejected malformed request")
            XCTAssertFalse(displayed.contains("op://"))
            XCTAssertFalse(displayed.contains("SECRET_ALIAS_CANARY"))
            XCTAssertFalse(displayed.contains("prod-account-123"))
            XCTAssertFalse(displayed.contains(Self.secretCanary))
            XCTAssertFalse(displayed.contains("/Users/alice/.ssh/id_rsa"))
        }
    }

    func testDaemonErrorDisplaySanitizesDaemonSuppliedCodeText() throws {
        let client = try SocketDaemonClient(
            transport: MemoryLineTransport(
                reads: [Self.errorResponse(code: "op://Example Vault/Item/token", message: Self.secretCanary)]
            )
        )

        XCTAssertThrowsError(try client.fetchPendingRequest()) { error in
            XCTAssertEqual(error as? SocketDaemonClientError, .daemonError("unknown", "daemon returned an error"))
            let displayed = String(describing: error)
            XCTAssertEqual(displayed, "daemon error unknown: daemon returned an error")
            XCTAssertFalse(displayed.contains("op://"))
            XCTAssertFalse(displayed.contains(Self.secretCanary))
        }
    }

    func testUnexpectedResponseTypeDoesNotEchoDaemonText() throws {
        let response = try Self.rawResponse(type: Self.secretCanary)
        let client = SocketDaemonClient(
            transport: MemoryLineTransport(reads: [response])
        )

        assertDisplayedError(
            from: { _ = try client.fetchPendingRequest() },
            equals: "invalid daemon response: unexpected response type"
        )
    }

    func testInvalidPayloadDecodeErrorDoesNotEchoDaemonText() throws {
        let response = try Self.rawResponse(type: "ok", expiresAt: Self.secretCanary)
        let client = SocketDaemonClient(
            transport: MemoryLineTransport(reads: [response])
        )

        assertDisplayedError(
            from: { _ = try client.fetchPendingRequest() },
            equals: "invalid daemon response: malformed daemon response payload"
        )
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
