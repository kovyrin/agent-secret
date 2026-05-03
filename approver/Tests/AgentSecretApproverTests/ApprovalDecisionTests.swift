@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalDecisionTests: XCTestCase {
    func testFactoriesPopulateReusableUsesOnlyForReusableApproval() {
        XCTAssertNil(ApprovalDecision.approveOnce(requestID: "req_1", nonce: "nonce_1").reusableUses)
        XCTAssertNil(ApprovalDecision.deny(requestID: "req_1", nonce: "nonce_1").reusableUses)
        XCTAssertNil(ApprovalDecision.timeout(requestID: "req_1", nonce: "nonce_1").reusableUses)
        XCTAssertEqual(
            ApprovalDecision
                .approveReusable(requestID: "req_1", nonce: "nonce_1", reusableUses: 3)
                .reusableUses,
            3
        )
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
}
