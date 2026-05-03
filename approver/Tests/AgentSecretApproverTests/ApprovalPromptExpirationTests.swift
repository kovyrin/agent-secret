@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalPromptExpirationTests: XCTestCase {
    func testExpirationTimesOutWhenPromptClockReachesExpiry() {
        let expiresAt = Date(timeIntervalSince1970: 1_800_000_000)
        let expiration = ApprovalPromptExpiration(expiresAt: expiresAt)

        XCTAssertNil(expiration.timeoutDecision(at: expiresAt.addingTimeInterval(-0.001)))
        XCTAssertEqual(expiration.timeoutDecision(at: expiresAt), .timeout)
        XCTAssertEqual(expiration.timeoutDecision(at: expiresAt.addingTimeInterval(1)), .timeout)
    }

    func testLateDecisionsBecomeTimeouts() {
        let expiresAt = Date(timeIntervalSince1970: 1_800_000_000)
        let expiration = ApprovalPromptExpiration(expiresAt: expiresAt)

        XCTAssertEqual(
            expiration.guardDecision(.approveOnce, at: expiresAt.addingTimeInterval(-0.001)),
            .approveOnce
        )
        XCTAssertEqual(expiration.guardDecision(.approveOnce, at: expiresAt), .timeout)
        XCTAssertEqual(expiration.guardDecision(.approveReusable, at: expiresAt.addingTimeInterval(1)), .timeout)
        XCTAssertEqual(expiration.guardDecision(.deny, at: expiresAt.addingTimeInterval(1)), .timeout)
        XCTAssertEqual(expiration.guardDecision(.timeout, at: expiresAt.addingTimeInterval(1)), .timeout)
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
