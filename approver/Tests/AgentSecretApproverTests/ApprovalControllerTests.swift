import Foundation
import XCTest

@testable import AgentSecretApprover

final class ApprovalControllerTests: XCTestCase {
    private let canarySecretValue = "synthetic-secret-value"

    func testSubmitsApproveOnceDecisionWithoutSecretValues() throws {
        let request = ApprovalRequest.sample
        let client = MockDaemonClient(request: request)
        let logger = RecordingLogger()
        let controller = ApprovalController(
            client: client,
            presenter: StaticDecisionPresenter(decision: .approveOnce),
            logger: logger
        )

        let decision = try controller.run()

        XCTAssertEqual(
            decision,
            ApprovalDecision(
                requestID: request.requestID,
                nonce: request.nonce,
                decision: .approveOnce
            )
        )
        XCTAssertEqual(client.submittedDecision, decision)

        let encoded = String(data: try JSONEncoder().encode(decision), encoding: .utf8) ?? ""
        XCTAssertFalse(encoded.contains("op://"))
        XCTAssertFalse(encoded.contains("EXAMPLE_TOKEN"))
        XCTAssertFalse(logger.events.contains { $0.contains("op://") })
    }

    func testReusableDecisionCarriesThreeUseLimit() throws {
        let request = ApprovalRequest.sample
        let client = MockDaemonClient(request: request)
        let controller = ApprovalController(
            client: client,
            presenter: StaticDecisionPresenter(decision: .approveReusable),
            logger: RecordingLogger()
        )

        let decision = try controller.run()

        XCTAssertEqual(decision.decision, .approveReusable)
        XCTAssertEqual(decision.reusableUses, 3)
    }

    func testSharedApprovalFixturesDecode() throws {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let request = try decoder.decode(
            ApprovalRequest.self,
            from: fixtureData("approval_request")
        )
        XCTAssertEqual(request.requestID, "req_123")
        XCTAssertEqual(request.nonce, "nonce_456")
        XCTAssertEqual(request.resolvedExecutable, "/opt/homebrew/bin/terraform")
        XCTAssertEqual(request.overrideEnv, true)
        XCTAssertEqual(request.overriddenAliases, ["EXAMPLE_TOKEN"])
        XCTAssertEqual(request.reusableUses, 3)
        XCTAssertEqual(request.secrets.first?.ref, "op://Example Vault/Example Item/token")

        let decision = try decoder.decode(
            ApprovalDecision.self,
            from: fixtureData("approval_decision")
        )
        XCTAssertEqual(decision.requestID, "req_123")
        XCTAssertEqual(decision.nonce, "nonce_456")
        XCTAssertEqual(decision.decision, .approveReusable)
        XCTAssertEqual(decision.reusableUses, 3)
    }

    func testViewModelContainsApprovalContextWithoutSecretValuesOrDebugIdentifiers() throws {
        var request = ApprovalRequest.sample
        request.overrideEnv = true
        request.overriddenAliases = ["EXAMPLE_TOKEN"]
        let viewModel = ApprovalRequestViewModel(
            request: request,
            now: Date(timeIntervalSince1970: 1_799_999_880)
        )

        XCTAssertTrue(viewModel.renderedText.contains("Run Terraform plan"))
        XCTAssertTrue(viewModel.renderedText.contains("/tmp/project"))
        XCTAssertTrue(viewModel.renderedText.contains("EXAMPLE_TOKEN -> op://Example Vault/Example Item/token"))
        XCTAssertTrue(viewModel.renderedText.contains("Resolved binary: /opt/homebrew/bin/terraform"))
        XCTAssertTrue(viewModel.renderedText.contains("Time remaining: 2m"))
        XCTAssertTrue(viewModel.renderedText.contains("Will replace existing variables: EXAMPLE_TOKEN"))
        XCTAssertFalse(viewModel.renderedText.contains(canarySecretValue))
        XCTAssertFalse(viewModel.renderedText.contains(request.requestID))
        XCTAssertFalse(viewModel.renderedText.contains(request.nonce))
    }

    func testSocketDaemonClientFetchesAndSubmitsDecision() throws {
        let payload = try String(data: fixtureData("approval_request"), encoding: .utf8)?
            .replacingOccurrences(
                of: #""expiresAt": "2027-01-15T08:00:00Z""#,
                with: #""expiresAt": "2027-01-15T08:00:00.123456Z""#
            ) ?? "{}"
        let requestData = try daemonEnvelope(
            type: "ok",
            requestID: "req_123",
            nonce: "nonce_456",
            payload: payload
        )
        let transport = MemoryLineTransport(reads: [requestData, okEnvelope()])
        let client = SocketDaemonClient(transport: transport)

        let request = try client.fetchPendingRequest()
        XCTAssertEqual(request.requestID, "req_123")
        try client.submit(
            ApprovalDecision(
                requestID: request.requestID,
                nonce: request.nonce,
                decision: .approveOnce
            )
        )

        let written = transport.writtenStrings.joined(separator: "\n")
        XCTAssertTrue(written.contains("approval.pending"))
        XCTAssertTrue(written.contains("approval.decision"))
        XCTAssertFalse(written.contains(canarySecretValue))
    }

    func testSocketDaemonClientReportsDaemonErrors() throws {
        let errorLine = """
        {"payload":{"code":"stale_approval","message":"stale approval response"},"type":"error","version":1}
        """.data(using: .utf8)!
        let client = SocketDaemonClient(transport: MemoryLineTransport(reads: [errorLine]))

        XCTAssertThrowsError(try client.fetchPendingRequest()) { error in
            XCTAssertEqual(
                error as? SocketDaemonClientError,
                .daemonError("stale_approval", "stale approval response")
            )
        }
    }
}

private final class RecordingLogger: ApprovalLogger {
    private(set) var events: [String] = []

    func record(_ event: String, requestID: String?) {
        events.append("\(event):\(requestID ?? "none")")
    }
}

private final class MemoryLineTransport: LineTransport {
    private var reads: [Data]
    private(set) var writtenStrings: [String] = []

    init(reads: [Data]) {
        self.reads = reads
    }

    func writeLine(_ data: Data) throws {
        writtenStrings.append(String(data: data, encoding: .utf8) ?? "")
    }

    func readLine() throws -> Data {
        guard !reads.isEmpty else {
            throw SocketDaemonClientError.disconnected
        }
        return reads.removeFirst()
    }
}

private extension ApprovalRequest {
    static var sample: ApprovalRequest {
        ApprovalRequest(
            requestID: "req_123",
            nonce: "nonce_456",
            reason: "Run Terraform plan for staging",
            command: ["/opt/homebrew/bin/terraform", "plan"],
            cwd: "/tmp/project",
            resolvedExecutable: "/opt/homebrew/bin/terraform",
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            secrets: [
                RequestedSecret(
                    alias: "EXAMPLE_TOKEN",
                    ref: "op://Example Vault/Example Item/token"
                )
            ]
        )
    }
}

private func fixtureData(_ name: String) throws -> Data {
    let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "json"))
    return try Data(contentsOf: url)
}

private func daemonEnvelope(
    type: String,
    requestID: String,
    nonce: String,
    payload: String
) throws -> Data {
    let json = """
    {"nonce":"\(nonce)","payload":\(payload),"request_id":"\(requestID)","type":"\(type)","version":1}
    """
    return Data(json.utf8)
}

private func okEnvelope() -> Data {
    Data(#"{"type":"ok","version":1}"#.utf8)
}
