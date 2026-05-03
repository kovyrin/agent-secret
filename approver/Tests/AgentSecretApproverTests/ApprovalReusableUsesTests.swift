@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalReusableUsesTests: XCTestCase {
    private struct NoopApprovalLogger: ApprovalLogger {
        func record(_: String, requestID _: String?) {
            /* Intentionally ignored. */
        }
    }

    private static let sampleExpiration: TimeInterval = 1_800_000_000
    private static let viewModelNow: TimeInterval = 1_799_999_880

    private static func request(reusableUses: Int) -> ApprovalRequest {
        ApprovalRequest(
            requestID: "req_reusable_uses",
            nonce: "nonce_reusable_uses",
            reason: "Run reusable approval test",
            command: ["/usr/bin/env", "true"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: sampleExpiration),
            secrets: [
                RequestedSecret(
                    alias: "EXAMPLE_TOKEN",
                    ref: "op://Example Vault/Example Item/token",
                    account: "Work"
                )
            ],
            resolvedExecutable: "/usr/bin/env",
            reusableUses: reusableUses
        )
    }

    func testApprovalRequestBoundsReusableUsesBeforeDisplay() {
        let lowRequest: ApprovalRequest = Self.request(reusableUses: 0)
        let highRequest: ApprovalRequest = Self.request(reusableUses: ApprovalRequest.maxReusableUses + 1)
        let validRequest: ApprovalRequest = Self.request(reusableUses: 2)

        XCTAssertEqual(lowRequest.reusableUses, ApprovalRequest.defaultReusableUses)
        XCTAssertEqual(highRequest.reusableUses, ApprovalRequest.defaultReusableUses)
        XCTAssertEqual(validRequest.reusableUses, 2)

        let viewModel = ApprovalRequestViewModel(
            request: validRequest,
            now: Date(timeIntervalSince1970: Self.viewModelNow)
        )
        XCTAssertEqual(viewModel.reusableUses, validRequest.reusableUses)
    }

    @MainActor
    func testReusableDecisionEchoesDisplayedRequestUseLimit() async throws {
        let request: ApprovalRequest = Self.request(reusableUses: 2)
        let viewModel = ApprovalRequestViewModel(
            request: request,
            now: Date(timeIntervalSince1970: Self.viewModelNow)
        )
        let client = MockDaemonClient(request: request)
        let controller = ApprovalController(
            client: client,
            presenter: StaticDecisionPresenter(decision: .approveReusable),
            logger: NoopApprovalLogger()
        )

        let decision: ApprovalDecision = try await controller.run()

        XCTAssertEqual(viewModel.reusableUses, 2)
        XCTAssertEqual(decision.decision, .approveReusable)
        XCTAssertEqual(decision.reusableUses, viewModel.reusableUses)
        XCTAssertEqual(client.submittedDecision, decision)
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
