@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalControllerExpirationTests: XCTestCase {
    private struct NoopApprovalLogger: ApprovalLogger {
        func record(_: String, requestID _: String?) {
            /* Intentionally ignored. */
        }
    }

    private static let sampleExpiration: TimeInterval = 1_800_000_000

    private static var request: ApprovalRequest {
        ApprovalRequest(
            requestID: "req_expired",
            nonce: "nonce_expired",
            reason: "Run expired approval test",
            command: ["/usr/bin/env", "true"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: sampleExpiration),
            resources: [
                RequestedResource(
                    alias: "EXAMPLE_TOKEN",
                    ref: "op://Example Vault/Example Item/token",
                    account: "Work"
                )
            ],
            resolvedExecutable: "/usr/bin/env"
        )
    }

    @MainActor
    func testSubmitsTimeoutWhenApproveOnceRequestExpired() async throws {
        let request: ApprovalRequest = Self.request
        let client = RecordingDaemonClient(request: request)
        let controller = ApprovalController(
            client: client,
            presenter: FixedDecisionPresenter(decision: .approveOnce),
            logger: NoopApprovalLogger()
        ) {
            Date(timeIntervalSince1970: Self.sampleExpiration)
        }

        let decision: ApprovalDecision = try await controller.run()

        XCTAssertEqual(decision, .timeout(for: request))
        XCTAssertEqual(client.submittedDecision, decision)
    }

    @MainActor
    func testSubmitsTimeoutWhenReusableRequestExpired() async throws {
        let request: ApprovalRequest = Self.request
        let client = RecordingDaemonClient(request: request)
        let controller = ApprovalController(
            client: client,
            presenter: FixedDecisionPresenter(decision: .approveReusable),
            logger: NoopApprovalLogger()
        ) {
            Date(timeIntervalSince1970: Self.sampleExpiration + 1)
        }

        let decision: ApprovalDecision = try await controller.run()

        XCTAssertEqual(decision, .timeout(for: request))
        XCTAssertNil(decision.reusableUses)
        XCTAssertEqual(client.submittedDecision, decision)
    }

    @MainActor
    func testSubmitsDenyWhenExpiredRequestDenied() async throws {
        let request: ApprovalRequest = Self.request
        let client = RecordingDaemonClient(request: request)
        let controller = ApprovalController(
            client: client,
            presenter: FixedDecisionPresenter(decision: .deny),
            logger: NoopApprovalLogger()
        ) {
            Date(timeIntervalSince1970: Self.sampleExpiration + 1)
        }

        let decision: ApprovalDecision = try await controller.run()

        XCTAssertEqual(decision, .deny(for: request))
        XCTAssertEqual(client.submittedDecision, decision)
    }
}
