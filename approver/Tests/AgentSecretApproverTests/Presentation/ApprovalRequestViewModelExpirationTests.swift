@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalRequestViewModelExpirationTests: XCTestCase {
    private static let sampleExpiration: TimeInterval = 1_800_000_000
    private static let viewModelNow: TimeInterval = 1_799_999_880
    private static let boundProcessPID = 560 * 100 + 29
    private static let creatorProcessPID = 560 * 100 + 30

    func testViewModelMarksLongCommandsInspectable() {
        let script = String(repeating: "terraform import cloudflare_record.long_name ", count: 3)
        let request = ApprovalRequest(
            requestID: "req_long",
            nonce: "nonce_long",
            reason: "Run import",
            command: ["/bin/sh", "-c", script],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: Self.sampleExpiration),
            resources: [
                RequestedResource(alias: "DEPLOY_TOKEN", ref: "op://Shared/Deploy/token", account: "Work")
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
            resources: [
                RequestedResource(alias: "DEPLOY_TOKEN", ref: "op://Shared/Deploy/token", account: "Work")
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
        XCTAssertEqual(liveViewModel.scopeSummary, "Same command only • max 3 uses\nexpires in 2 sec")
        XCTAssertTrue(expiredViewModel.isExpired)
        XCTAssertEqual(expiredViewModel.compactTimeRemaining, "expired")
        XCTAssertEqual(expiredViewModel.promptQuestion, "This secret access request has expired.")
        XCTAssertEqual(expiredViewModel.accessSummary, "can no longer receive access.")
        XCTAssertEqual(expiredViewModel.scopeSummary, "Same command only • max 3 uses\nrequest expired")
        XCTAssertTrue(expiredViewModel.footerMessage.contains("expired before approval"))
        XCTAssertTrue(expiredViewModel.renderedText.contains("Time remaining: expired"))
    }

    func testSessionScopeShowsApprovedDurationWithoutCountingDown() {
        let request = ApprovalRequest(
            requestID: "req_session",
            nonce: "nonce_session",
            reason: "Run a bounded workflow",
            command: ["agent-secret", "session", "create"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: Self.viewModelNow + 120),
            resources: [
                RequestedResource(alias: "DEPLOY_TOKEN", ref: "op://Shared/Deploy/token", account: "Work")
            ],
            resolvedExecutable: "/usr/local/bin/agent-secret",
            operation: .sessionCreate,
            allowsReusable: false,
            accessDurationSeconds: 300,
            sessionBinding: SessionBindingInfo(
                mode: "ancestor_name",
                boundProcess: SessionBindingProcess(
                    pid: Self.boundProcessPID,
                    name: "codex",
                    path: "/Applications/Codex.app/Contents/MacOS/Codex"
                ),
                creatorProcess: SessionBindingProcess(
                    pid: Self.creatorProcessPID,
                    name: "agent-secret",
                    path: "/usr/local/bin/agent-secret"
                )
            )
        )

        let initialViewModel = ApprovalRequestViewModel(
            request: request,
            now: Date(timeIntervalSince1970: Self.viewModelNow)
        )
        let laterViewModel = ApprovalRequestViewModel(
            request: request,
            now: Date(timeIntervalSince1970: Self.viewModelNow + 60)
        )

        XCTAssertEqual(initialViewModel.promptQuestion, "Allow codex (pid 56029) to use the following secret?")
        XCTAssertEqual(initialViewModel.scopeSummary, "One approved session\nAccess for 5 minutes after approval")
        XCTAssertEqual(laterViewModel.scopeSummary, initialViewModel.scopeSummary)
        XCTAssertEqual(initialViewModel.compactTimeRemaining, "2 minutes")
        XCTAssertEqual(laterViewModel.compactTimeRemaining, "1 minute")
    }
}
