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
        func testAlertButtonMappingDefaultsToDeny() {
            XCTAssertEqual(
                AppKitApprovalPresenter.decision(for: .alertFirstButtonReturn),
                .deny
            )
            XCTAssertEqual(
                AppKitApprovalPresenter.decision(for: .alertSecondButtonReturn),
                .approveOnce
            )
            XCTAssertEqual(
                AppKitApprovalPresenter.decision(for: .alertThirdButtonReturn),
                .approveReusable
            )
            XCTAssertEqual(AppKitApprovalPresenter.decision(for: .abort), .deny)
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }
#endif
