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
            secrets: [
                RequestedSecret(
                    alias: "EXAMPLE_TOKEN",
                    ref: "op://Example Vault/Example Item/token",
                    account: "Work"
                )
            ],
            resolvedExecutable: "/opt/homebrew/bin/terraform",
            reusableUses: expectedReusableUses
        )
    }

    private static var multiSecretRequest: ApprovalRequest {
        ApprovalRequest(
            requestID: "req_caution_multi",
            nonce: "nonce_caution_multi",
            reason: "Run integration checks",
            command: ["/usr/bin/env"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: sampleExpiration),
            secrets: multiSecrets,
            resolvedExecutable: "/usr/bin/env",
            reusableUses: expectedReusableUses
        )
    }

    private static var multiSecrets: [RequestedSecret] {
        [
            RequestedSecret(alias: "LOGIN", ref: "op://Private/Github/username"),
            RequestedSecret(alias: "GITHUB_TOKEN", ref: "op://Private/Github/token"),
            RequestedSecret(alias: "GITHUB_EMAIL", ref: "op://Private/Github/email"),
            RequestedSecret(alias: "DB_HOST", ref: "op://Database/App/host"),
            RequestedSecret(alias: "DB_USER", ref: "op://Database/App/user"),
            RequestedSecret(alias: "DB_PASSWORD", ref: "op://Database/App/password"),
            RequestedSecret(alias: "DB_NAME", ref: "op://Database/App/name"),
            RequestedSecret(alias: "OPENAI_API_KEY", ref: "op://OpenAI/Platform/api_key"),
            RequestedSecret(alias: "OPENAI_ORG_ID", ref: "op://OpenAI/Platform/org_id"),
            RequestedSecret(alias: "OPENAI_PROJECT_ID", ref: "op://OpenAI/Platform/project_id")
        ]
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

    func testMutableExecutableWarningIsVisibleOutsideCollapsedDetails() {
        var request: ApprovalRequest = Self.multiSecretRequest
        request.allowMutableExecutable = true
        let viewModel = ApprovalRequestViewModel(
            request: request,
            now: Date(timeIntervalSince1970: Self.viewModelNow)
        )

        XCTAssertTrue(viewModel.highScopeWarning)
        XCTAssertTrue(viewModel.printsEnvironmentWarning)
        XCTAssertEqual(viewModel.cautionMessages.count, 1)
        XCTAssertTrue(viewModel.cautionMessages[0].contains("Mutable executable opt-in"))
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
