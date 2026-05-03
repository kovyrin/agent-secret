@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalMetadataSanitizationTests: XCTestCase {
    private static let sampleExpiration: TimeInterval = 1_800_000_000
    private static let viewModelNow: TimeInterval = 1_799_999_880

    func testNonCommandMetadataEscapesSpoofingScalars() throws {
        let request = ApprovalRequest(
            requestID: "req_metadata_spoof",
            nonce: "nonce_metadata_spoof",
            reason: "Deploy\nAccount: Work\u{202E}\t",
            command: ["/bin/echo", "safe\u{202E}txt"],
            cwd: "/tmp/project\rspoof\u{200D}",
            expiresAt: Date(timeIntervalSince1970: Self.sampleExpiration),
            secrets: [
                RequestedSecret(
                    alias: "DEPLOY_TOKEN",
                    ref: "op://Shared\nInjected/Item\u{202E}/token",
                    account: "Work\u{202E}\nAdmin"
                )
            ],
            resolvedExecutable: "/tmp/bin/tool\u{202E}txt",
            overrideEnv: true,
            overriddenAliases: ["DEPLOY_TOKEN\nROOT", "API\u{202E}KEY"]
        )

        let viewModel = ApprovalRequestViewModel(
            request: request,
            now: Date(timeIntervalSince1970: Self.viewModelNow)
        )

        try assertSpoofingMetadataEscaped(viewModel)
    }

    private func assertSpoofingMetadataEscaped(
        _ viewModel: ApprovalRequestViewModel,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let secret = try XCTUnwrap(viewModel.requestedSecrets.first, file: file, line: line)
        XCTAssertEqual(viewModel.reason, "Deploy\\nAccount: Work\\u202E\\t")
        XCTAssertEqual(viewModel.cwd, "/tmp/project\\rspoof\\u200D")
        XCTAssertEqual(viewModel.projectFolder, "/tmp/project\\rspoof\\u200D")
        XCTAssertEqual(viewModel.executable, "tool\\u202Etxt")
        XCTAssertEqual(viewModel.resolvedExecutable, "/tmp/bin/tool\\u202Etxt")
        XCTAssertEqual(secret.ref, "op://Shared\\nInjected/Item\\u202E/token")
        XCTAssertEqual(secret.account, "Work\\u202E\\nAdmin")
        XCTAssertEqual(secret.accountLabel, "Account: Work\\u202E\\nAdmin")
        XCTAssertEqual(secret.vaultName, "Shared\\nInjected")
        XCTAssertEqual(secret.vaultScopeName, "Work\\u202E\\nAdmin / Shared\\nInjected")
        XCTAssertEqual(
            viewModel.secretRows,
            [
                "DEPLOY_TOKEN [Account: Work\\u202E\\nAdmin] -> " +
                    "op://Shared\\nInjected/Item\\u202E/token"
            ]
        )
        XCTAssertEqual(
            viewModel.overrideWarning,
            "Will replace existing variables: DEPLOY_TOKEN\\nROOT, API\\u202EKEY"
        )
        XCTAssertTrue(viewModel.requestInspectionText.contains("- DEPLOY_TOKEN\\nROOT"))
        XCTAssertTrue(viewModel.requestInspectionText.contains("- API\\u202EKEY"))
        XCTAssertFalse(viewModel.requestInspectionText.contains("\u{202E}"))
        XCTAssertFalse(viewModel.requestInspectionText.contains("\nROOT"))
        XCTAssertEqual(viewModel.command, "'/bin/echo' $'safe\\u202Etxt'")
        XCTAssertFalse(viewModel.renderedText.contains("\u{202E}"))
        XCTAssertFalse(viewModel.renderedText.contains("\u{200D}"))
        XCTAssertFalse(viewModel.renderedText.contains("\r"))
        XCTAssertFalse(viewModel.renderedText.contains("\t"))
        XCTAssertTrue(viewModel.renderedText.contains("Reason: Deploy\\nAccount: Work\\u202E\\t"))
        XCTAssertTrue(
            viewModel.renderedText.contains(
                "DEPLOY_TOKEN [Account: Work\\u202E\\nAdmin] -> " +
                    "op://Shared\\nInjected/Item\\u202E/token"
            )
        )
    }

    func testPrintableMetadataRemainsReadable() throws {
        let request = ApprovalRequest(
            requestID: "req_metadata_readable",
            nonce: "nonce_metadata_readable",
            reason: "Deploy café service 🚀",
            command: ["/usr/bin/env", "deploy"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: Self.sampleExpiration),
            secrets: [
                RequestedSecret(alias: "DEPLOY_TOKEN", ref: "op://Shared/Deploy/token", account: "Work")
            ],
            resolvedExecutable: "/usr/bin/env"
        )

        let viewModel = ApprovalRequestViewModel(
            request: request,
            now: Date(timeIntervalSince1970: Self.viewModelNow)
        )
        let secret = try XCTUnwrap(viewModel.requestedSecrets.first)

        XCTAssertEqual(viewModel.reason, "Deploy café service 🚀")
        XCTAssertEqual(viewModel.cwd, "/tmp/project")
        XCTAssertEqual(viewModel.resolvedExecutable, "/usr/bin/env")
        XCTAssertEqual(secret.accountLabel, "Account: Work")
        XCTAssertEqual(secret.ref, "op://Shared/Deploy/token")
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
