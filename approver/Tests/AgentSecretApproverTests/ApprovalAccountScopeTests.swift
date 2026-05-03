@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalAccountScopeTests: XCTestCase {
    private static let sampleExpiration: TimeInterval = 1_800_000_000
    private static let viewModelNow: TimeInterval = 1_799_999_880

    func testViewModelDistinguishesSameReferenceAcrossAccounts() {
        let request = ApprovalRequest(
            requestID: "req_accounts",
            nonce: "nonce_accounts",
            reason: "Run deploy",
            command: ["/usr/bin/env", "deploy"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: Self.sampleExpiration),
            secrets: [
                RequestedSecret(alias: "PERSONAL_TOKEN", ref: "op://Shared/Deploy/token", account: "Personal"),
                RequestedSecret(alias: "WORK_TOKEN", ref: "op://Shared/Deploy/token", account: "Work")
            ],
            resolvedExecutable: "/usr/bin/env"
        )
        let viewModel = ApprovalRequestViewModel(
            request: request,
            now: Date(timeIntervalSince1970: Self.viewModelNow)
        )

        XCTAssertEqual(viewModel.requestedSecrets.map(\.account), ["Personal", "Work"])
        XCTAssertEqual(viewModel.requestedSecrets.map(\.accountLabel), ["Account: Personal", "Account: Work"])
        XCTAssertTrue(
            viewModel.renderedText.contains(
                "PERSONAL_TOKEN [Account: Personal] -> op://Shared/Deploy/token"
            )
        )
        XCTAssertTrue(viewModel.renderedText.contains("WORK_TOKEN [Account: Work] -> op://Shared/Deploy/token"))
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
