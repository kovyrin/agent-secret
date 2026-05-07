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
    }

    private static let expectedProtocolVersion: Int = 1
    private static let secretCanary: String = "synthetic-secret-value"

    private static func errorResponse(code: String, message: String) throws -> Data {
        let object: [String: Any] = [
            "payload": [
                "code": code,
                "message": message
            ],
            "type": "error",
            "version": expectedProtocolVersion
        ]
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private static func rawResponse(type: String, expiresAt: String = "2030-01-01T00:00:00Z") throws -> Data {
        let object: [String: Any] = [
            "nonce": "nonce_456",
            "payload": [
                "command": ["/usr/bin/env", "echo"],
                "cwd": "/tmp/project",
                "expires_at": expiresAt,
                "nonce": "nonce_456",
                "reason": "Run deployment",
                "request_id": "req_123",
                "resolved_executable": "/usr/bin/env",
                "resources": [
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

    func testDaemonErrorMessageRedactsDaemonSuppliedMessageText() throws {
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
                .daemonError(.badRequest)
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

    func testDaemonErrorMessageSanitizesDaemonSuppliedCodeText() throws {
        let client = try SocketDaemonClient(
            transport: MemoryLineTransport(
                reads: [Self.errorResponse(code: "op://Example Vault/Item/token", message: Self.secretCanary)]
            )
        )

        XCTAssertThrowsError(try client.fetchPendingRequest()) { error in
            XCTAssertEqual(error as? SocketDaemonClientError, .daemonError(.unknown))
            let displayed = String(describing: error)
            XCTAssertEqual(displayed, "daemon error unknown: daemon returned an error")
            XCTAssertFalse(displayed.contains("op://"))
            XCTAssertFalse(displayed.contains(Self.secretCanary))
        }
    }

    func testDaemonErrorMessageIncludesDaemonStopAndFallbackCodes() {
        XCTAssertEqual(DaemonErrorMessage.message(for: .daemonStopped), "daemon stopped")
        XCTAssertEqual(DaemonErrorMessage.message(for: .requestFailed), "daemon request failed")
        XCTAssertEqual(DaemonErrorMessage.message(for: .contextCanceled), "daemon request was canceled")
        XCTAssertEqual(DaemonErrorMessage.message(for: .contextDeadlineExceeded), "daemon request deadline expired")
        XCTAssertEqual(DaemonErrorMessage.message(for: .resolveFailed), "daemon failed to resolve approved secret")
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

        XCTAssertThrowsError(try client.fetchPendingRequest()) { error in
            guard case let .malformedResponse(message, underlying) = error as? SocketDaemonClientError else {
                XCTFail("error = \(error), want malformedResponse")
                return
            }
            XCTAssertEqual(message, "malformed daemon response payload")
            XCTAssertTrue(underlying is DecodingError)

            let displayed = String(describing: error)
            XCTAssertEqual(displayed, "invalid daemon response: malformed daemon response payload")
            XCTAssertFalse(displayed.contains("op://"))
            XCTAssertFalse(displayed.contains("SECRET_ALIAS_CANARY"))
            XCTAssertFalse(displayed.contains("prod-account-123"))
            XCTAssertFalse(displayed.contains(Self.secretCanary))
        }
    }
}
