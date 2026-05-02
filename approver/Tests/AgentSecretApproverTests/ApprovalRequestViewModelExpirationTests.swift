@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalRequestViewModelExpirationTests: XCTestCase {
    private static let sampleExpiration: TimeInterval = 1_800_000_000
    private static let viewModelNow: TimeInterval = 1_799_999_880

    func testViewModelMarksLongCommandsInspectable() {
        let script = String(repeating: "terraform import cloudflare_record.long_name ", count: 3)
        let request = ApprovalRequest(
            requestID: "req_long",
            nonce: "nonce_long",
            reason: "Run import",
            command: ["/bin/sh", "-c", script],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: Self.sampleExpiration),
            secrets: [
                RequestedSecret(alias: "DEPLOY_TOKEN", ref: "op://Shared/Deploy/token")
            ],
            resolvedExecutable: "/bin/sh"
        )
        let viewModel = ApprovalRequestViewModel(request: request, now: Date(timeIntervalSince1970: Self.viewModelNow))

        XCTAssertTrue(viewModel.commandNeedsInspector)
    }

    func testViewModelUpdatesCountdownAsPromptClockAdvances() {
        let request = ApprovalRequest(
            requestID: "req_expiring",
            nonce: "nonce_expiring",
            reason: "Run deploy",
            command: ["/usr/bin/env", "deploy"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: Self.viewModelNow + 2),
            secrets: [
                RequestedSecret(alias: "DEPLOY_TOKEN", ref: "op://Shared/Deploy/token")
            ],
            resolvedExecutable: "/usr/bin/env"
        )

        let liveViewModel = ApprovalRequestViewModel(
            request: request,
            now: Date(timeIntervalSince1970: Self.viewModelNow)
        )
        let expiredViewModel = ApprovalRequestViewModel(
            request: request,
            now: Date(timeIntervalSince1970: Self.viewModelNow + 2)
        )

        XCTAssertFalse(liveViewModel.isExpired)
        XCTAssertEqual(liveViewModel.compactTimeRemaining, "2 sec")
        XCTAssertTrue(liveViewModel.scopeSummary.contains("expires in 2 sec"))
        XCTAssertTrue(expiredViewModel.isExpired)
        XCTAssertEqual(expiredViewModel.compactTimeRemaining, "expired")
        XCTAssertEqual(expiredViewModel.promptQuestion, "This secret access request has expired.")
        XCTAssertEqual(expiredViewModel.accessSummary, "can no longer receive access.")
        XCTAssertTrue(expiredViewModel.scopeSummary.contains("request expired"))
        XCTAssertTrue(expiredViewModel.footerMessage.contains("expired before approval"))
        XCTAssertTrue(expiredViewModel.renderedText.contains("Time remaining: expired"))
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
