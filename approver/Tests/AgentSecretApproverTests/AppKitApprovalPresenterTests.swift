@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(AppKit)
    import AppKit

    final class AppKitApprovalPresenterTests: XCTestCase {
        private static let fixedNow = Date(timeIntervalSince1970: 1_800_000_000)

        private static func approvalRequest(expiresAt: Date) -> ApprovalRequest {
            ApprovalRequest(
                requestID: "req_expired",
                nonce: "nonce_expired",
                reason: "Run a command",
                command: ["/usr/bin/env", "printenv", "TOKEN"],
                cwd: "/tmp/project",
                expiresAt: expiresAt,
                secrets: [
                    RequestedSecret(alias: "TOKEN", ref: "op://Example/Item/token", account: "Work")
                ],
                resolvedExecutable: "/usr/bin/env"
            )
        }

        @MainActor
        func testExpiredRequestPreflightsToTimeoutBeforeOpeningModal() {
            let request = Self.approvalRequest(expiresAt: Self.fixedNow)

            XCTAssertEqual(
                AppKitApprovalPresenter.preflightDecision(for: request, now: Self.fixedNow),
                .timeout
            )
        }

        @MainActor
        func testUnexpiredRequestDoesNotPreflightToTimeout() {
            let request = Self.approvalRequest(expiresAt: Self.fixedNow.addingTimeInterval(0.001))

            XCTAssertNil(AppKitApprovalPresenter.preflightDecision(for: request, now: Self.fixedNow))
        }

        @MainActor
        func testModalStopIsDeferredUntilModalRunLoopTurns() {
            let stopper = CountingModalStopper()
            let coordinator = AppKitModalDecisionCoordinator(stopper: stopper)

            coordinator.complete(with: .timeout)

            XCTAssertEqual(coordinator.decision, .timeout)
            XCTAssertEqual(stopper.stopCount, 0)

            _ = RunLoop.main.run(mode: .modalPanel, before: Date().addingTimeInterval(0.1))

            XCTAssertEqual(stopper.stopCount, 1)
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }
#endif
