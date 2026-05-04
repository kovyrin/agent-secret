@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalDecisionTests: XCTestCase {
    func testFactoriesPopulateReusableUsesOnlyForReusableApproval() {
        let request = sampleRequest(reusableUses: 3)

        XCTAssertNil(ApprovalDecision.approveOnce(for: request).reusableUses)
        XCTAssertNil(ApprovalDecision.deny(for: request).reusableUses)
        XCTAssertNil(ApprovalDecision.timeout(for: request).reusableUses)
        XCTAssertEqual(
            ApprovalDecision
                .approveReusable(for: request)
                .reusableUses,
            3
        )
    }

    func testReusableApprovalFactoryNormalizesOutOfRangeUseLimits() {
        XCTAssertEqual(
            ApprovalDecision
                .approveReusable(for: sampleRequest(reusableUses: 0))
                .reusableUses,
            ApprovalRequest.defaultReusableUses
        )
        XCTAssertEqual(
            ApprovalDecision
                .approveReusable(for: sampleRequest(reusableUses: ApprovalRequest.maxReusableUses + 1))
                .reusableUses,
            ApprovalRequest.defaultReusableUses
        )
    }

    func testDecodeNormalizesOutOfRangeReusableApprovalUseLimits() throws {
        for reusableUses in [0, ApprovalRequest.maxReusableUses + 1] {
            let json = """
            {
                "requestID": "req_1",
                "nonce": "nonce_1",
                "decision": "approve_reusable",
                "reusableUses": \(reusableUses)
            }
            """

            XCTAssertEqual(
                try decode(json).reusableUses,
                ApprovalRequest.defaultReusableUses
            )
        }
    }

    func testDecodeRejectsReusableApprovalWithoutUseLimit() {
        let json = """
        {
            "requestID": "req_1",
            "nonce": "nonce_1",
            "decision": "approve_reusable"
        }
        """

        XCTAssertThrowsError(try decode(json))
    }

    func testDecodeRejectsUseLimitOnNonReusableDecisions() {
        for decision in ["approve_once", "deny", "timeout"] {
            let json = """
            {
                "requestID": "req_1",
                "nonce": "nonce_1",
                "decision": "\(decision)",
                "reusableUses": 3
            }
            """

            XCTAssertThrowsError(try decode(json))
        }
    }

    private func decode(_ json: String) throws -> ApprovalDecision {
        try JSONDecoder().decode(ApprovalDecision.self, from: Data(json.utf8))
    }

    private func sampleRequest(reusableUses: Int = ApprovalRequest.defaultReusableUses) -> ApprovalRequest {
        ApprovalRequest(
            requestID: "req_1",
            nonce: "nonce_1",
            reason: "Run tests",
            command: ["/usr/bin/true"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            secrets: [],
            reusableUses: reusableUses
        )
    }
}
