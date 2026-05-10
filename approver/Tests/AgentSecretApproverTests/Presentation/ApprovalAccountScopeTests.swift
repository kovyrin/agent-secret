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
            resources: [
                RequestedResource(alias: "PERSONAL_TOKEN", ref: "op://Shared/Deploy/token", account: "Personal"),
                RequestedResource(alias: "WORK_TOKEN", ref: "op://Shared/Deploy/token", account: "Work")
            ],
            resolvedExecutable: "/usr/bin/env"
        )
        let viewModel = ApprovalRequestViewModel(
            request: request,
            now: Date(timeIntervalSince1970: Self.viewModelNow)
        )

        XCTAssertEqual(viewModel.requestedResources.map(\.account), ["Personal", "Work"])
        XCTAssertEqual(viewModel.requestedResources.map(\.accountLabel), ["Account: Personal", "Account: Work"])
        XCTAssertEqual(viewModel.vaultGroups.map(\.vaultName), ["Personal / Shared", "Work / Shared"])
        XCTAssertTrue(
            viewModel.renderedText.contains(
                "PERSONAL_TOKEN [Account: Personal] -> op://Shared/Deploy/token"
            )
        )
        XCTAssertTrue(viewModel.renderedText.contains("WORK_TOKEN [Account: Work] -> op://Shared/Deploy/token"))
    }

    func testViewModelOmitsAccountChromeForDesktopDefaultAccount() {
        let request = ApprovalRequest(
            requestID: "req_default_account",
            nonce: "nonce_default_account",
            reason: "Run deploy",
            command: ["/usr/bin/env", "deploy"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: Self.sampleExpiration),
            resources: [
                RequestedResource(alias: "DEPLOY_TOKEN", ref: "op://Shared/Deploy/token", account: "")
            ],
            resolvedExecutable: "/usr/bin/env"
        )
        let viewModel = ApprovalRequestViewModel(
            request: request,
            now: Date(timeIntervalSince1970: Self.viewModelNow)
        )

        XCTAssertEqual(viewModel.requestedResources.map(\.account), [""])
        XCTAssertEqual(viewModel.requestedResources.map(\.accountLabel), [""])
        XCTAssertEqual(viewModel.vaultGroups.map(\.vaultName), ["Shared"])
        XCTAssertTrue(viewModel.renderedText.contains("DEPLOY_TOKEN -> op://Shared/Deploy/token"))
        XCTAssertFalse(viewModel.renderedText.contains("[Account:"))
    }
}
