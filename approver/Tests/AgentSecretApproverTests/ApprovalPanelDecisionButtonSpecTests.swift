@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(SwiftUI)
    final class ApprovalPanelDecisionButtonSpecTests: XCTestCase {
        private static let sampleExpiration: TimeInterval = 1_800_000_000
        private static let viewModelNow: TimeInterval = 1_799_999_880

        private static func sampleButtonSpecs(now: TimeInterval = viewModelNow) -> [ApprovalPanelDecisionButtonSpec] {
            let request = ApprovalRequest(
                requestID: "req_buttons",
                nonce: "nonce_buttons",
                reason: "Run deploy",
                command: ["/usr/bin/env", "deploy"],
                cwd: "/tmp/project",
                expiresAt: Date(timeIntervalSince1970: sampleExpiration),
                secrets: [
                    RequestedSecret(alias: "DEPLOY_TOKEN", ref: "op://Shared/Deploy/token")
                ],
                resolvedExecutable: "/usr/bin/env"
            )
            let viewModel = ApprovalRequestViewModel(
                request: request,
                now: Date(timeIntervalSince1970: now)
            )
            return ApprovalPanelDecisionButtonSpec.makeAll(viewModel: viewModel)
        }

        func testDenyIsTheOnlyDefaultApprovalPanelAction() {
            let specs = Self.sampleButtonSpecs()

            XCTAssertEqual(specs.map(\.decision), [.deny, .approveOnce, .approveReusable])
            XCTAssertEqual(
                specs.filter { spec in spec.keyboardShortcut == .defaultAction }.map(\.decision),
                [.deny]
            )
        }

        func testApprovalActionsRequirePointerSelection() throws {
            let specs = Self.sampleButtonSpecs()
            let approveOnce: ApprovalPanelDecisionButtonSpec = try XCTUnwrap(
                specs.first { spec in spec.decision == .approveOnce }
            )
            let approveReusable: ApprovalPanelDecisionButtonSpec = try XCTUnwrap(
                specs.first { spec in spec.decision == .approveReusable }
            )

            XCTAssertNil(approveOnce.keyboardShortcut)
            XCTAssertNil(approveReusable.keyboardShortcut)
            XCTAssertTrue(approveOnce.isEnabled)
            XCTAssertTrue(approveReusable.isEnabled)
            XCTAssertFalse(approveOnce.subtitle.localizedCaseInsensitiveContains("default"))
            XCTAssertFalse(approveReusable.subtitle.localizedCaseInsensitiveContains("default"))
        }

        func testDenyCopyDescribesReturnKeyDefault() throws {
            let deny: ApprovalPanelDecisionButtonSpec = try XCTUnwrap(
                Self.sampleButtonSpecs().first { spec in spec.decision == .deny }
            )

            XCTAssertEqual(deny.title, "Deny")
            XCTAssertTrue(deny.subtitle.localizedCaseInsensitiveContains("default"))
            XCTAssertTrue(deny.subtitle.localizedCaseInsensitiveContains("return"))
            XCTAssertEqual(deny.keyboardShortcut, .defaultAction)
        }

        func testExpiredRequestsDisableApprovalActions() throws {
            let specs = Self.sampleButtonSpecs(now: Self.sampleExpiration)
            let deny: ApprovalPanelDecisionButtonSpec = try XCTUnwrap(
                specs.first { spec in spec.decision == ApprovalDecisionKind.deny }
            )
            let approvalSpecs: [ApprovalPanelDecisionButtonSpec] = specs.filter(
                \ApprovalPanelDecisionButtonSpec.decision.requiresUnexpiredRequest
            )

            XCTAssertTrue(deny.isEnabled)
            XCTAssertEqual(deny.keyboardShortcut, .defaultAction)
            XCTAssertEqual(approvalSpecs.map(\.isEnabled), [false, false])
            XCTAssertTrue(approvalSpecs.allSatisfy { spec in spec.subtitle == "Request expired" })
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }
#endif
