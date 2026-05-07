@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalCautionWarningTests: XCTestCase {
    private static let expectedReusableUses: Int = 3
    private static let sampleExpiration: TimeInterval = 1_800_000_000
    private static let viewModelNow: TimeInterval = 1_799_999_880

    private static var sampleRequest: ApprovalRequest {
        ApprovalRequest(
            requestID: "req_caution_override",
            nonce: "nonce_caution_override",
            reason: "Run Terraform plan for staging",
            command: ["/opt/homebrew/bin/terraform", "plan"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: sampleExpiration),
            resources: [
                RequestedResource(
                    alias: "EXAMPLE_TOKEN",
                    ref: "op://Example Vault/Example Item/token",
                    account: "Work"
                )
            ],
            resolvedExecutable: "/opt/homebrew/bin/terraform",
            reusableUses: expectedReusableUses
        )
    }

    func testOverrideWarningIsVisibleOutsideCollapsedDetails() {
        var request: ApprovalRequest = Self.sampleRequest
        request.overrideEnv = true
        request.overriddenAliases = ["EXAMPLE_TOKEN", "PATH"]
        let viewModel = ApprovalRequestViewModel(
            request: request,
            now: Date(timeIntervalSince1970: Self.viewModelNow)
        )

        XCTAssertTrue(viewModel.overrideEnv)
        XCTAssertEqual(viewModel.overriddenAliases, ["EXAMPLE_TOKEN", "PATH"])
        XCTAssertTrue(viewModel.cautionMessages.contains { message in
            message.contains("Will replace existing variables: EXAMPLE_TOKEN, PATH")
        })
    }
}
