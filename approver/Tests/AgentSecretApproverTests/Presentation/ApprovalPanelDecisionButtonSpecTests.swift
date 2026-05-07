@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(SwiftUI)
    import SwiftUI

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
                resources: [
                    RequestedResource(alias: "DEPLOY_TOKEN", ref: "op://Shared/Deploy/token", account: "Work")
                ],
                resolvedExecutable: "/usr/bin/env"
            )
            let viewModel = ApprovalRequestViewModel(
                request: request,
                now: Date(timeIntervalSince1970: now)
            )
            return ApprovalPanelDecisionButtonSpec.makeAll(viewModel: viewModel)
        }

        func testAllowOnceIsTheOnlyDefaultApprovalPanelAction() {
            let specs = Self.sampleButtonSpecs()

            XCTAssertEqual(specs.map(\.decision), [.deny, .approveOnce, .approveReusable])
            XCTAssertEqual(
                specs.filter { spec in spec.keyboardShortcut == .defaultAction }.map(\.decision),
                [.approveOnce]
            )
        }

        func testDenyIsTheOnlyCancelApprovalPanelAction() {
            let specs = Self.sampleButtonSpecs()

            XCTAssertEqual(
                specs.filter { spec in spec.keyboardShortcut == .cancelAction }.map(\.decision),
                [.deny]
            )
        }

        func testReusableApprovalRequiresPointerSelection() throws {
            let specs = Self.sampleButtonSpecs()
            let approveOnce: ApprovalPanelDecisionButtonSpec = try XCTUnwrap(
                specs.first { spec in spec.decision == .approveOnce }
            )
            let approveReusable: ApprovalPanelDecisionButtonSpec = try XCTUnwrap(
                specs.first { spec in spec.decision == .approveReusable }
            )

            XCTAssertEqual(approveOnce.keyboardShortcut, .defaultAction)
            XCTAssertNil(approveReusable.keyboardShortcut)
            XCTAssertTrue(approveOnce.isEnabled)
            XCTAssertTrue(approveReusable.isEnabled)
            XCTAssertEqual(approveOnce.subtitle, "Enter")
            XCTAssertFalse(approveReusable.subtitle.localizedCaseInsensitiveContains("default"))
        }

        func testDenyCopyDescribesEscapeKey() throws {
            let deny: ApprovalPanelDecisionButtonSpec = try XCTUnwrap(
                Self.sampleButtonSpecs().first { spec in spec.decision == .deny }
            )

            XCTAssertEqual(deny.title, "Deny")
            XCTAssertEqual(deny.subtitle, "Esc")
            XCTAssertEqual(deny.keyboardShortcut, .cancelAction)
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
            XCTAssertEqual(deny.keyboardShortcut, .cancelAction)
            XCTAssertEqual(approvalSpecs.map(\.isEnabled), [false, false])
            XCTAssertTrue(approvalSpecs.allSatisfy { spec in spec.subtitle == "Request expired" })
        }
    }
#endif
