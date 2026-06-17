@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalRequestInspectionTests: XCTestCase {
    private static let canarySecretValue: String = "synthetic-secret-value"
    private static let sampleExpiration: TimeInterval = 1_800_000_000
    private static let viewModelNow: TimeInterval = 1_799_999_880

    private static var itemDescribeRequest: ApprovalRequest {
        ApprovalRequest(
            requestID: "req_item_describe",
            nonce: "nonce_item_describe",
            reason: "Inspect item metadata",
            command: ["agent-secret", "item", "describe", "op://Example Vault/Example Item"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: sampleExpiration),
            resources: [
                RequestedResource(
                    alias: "EXAMPLE_TOKEN",
                    ref: "op://Example Vault/Example Item/token",
                    account: "Work"
                )
            ],
            resolvedExecutable: "/Users/example/.local/bin/agent-secret",
            operation: .itemDescribe,
            allowsReusable: false
        )
    }

    private static var sessionCreateRequest: ApprovalRequest {
        ApprovalRequest(
            requestID: "req_session_create",
            nonce: "nonce_session_create",
            reason: "Deploy workflow",
            command: ["agent-secret", "session", "create", "--profile", "deploy"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: sampleExpiration),
            resources: [
                RequestedResource(
                    alias: "DEPLOY_TOKEN",
                    ref: "op://Example Vault/Deploy/token",
                    account: "Work"
                )
            ],
            resolvedExecutable: "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret",
            operation: .sessionCreate,
            allowsReusable: false,
            sessionBinding: SessionBindingInfo(
                mode: "ancestor_name",
                boundProcess: SessionBindingProcess(
                    pid: 501,
                    name: "zsh",
                    path: "/bin/zsh",
                    parentPID: 1
                ),
                creatorProcess: SessionBindingProcess(
                    pid: 502,
                    name: "agent-secret",
                    path: "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret"
                ),
                ancestorDepth: 1,
                ancestorName: "zsh",
                ancestorNames: ["Codex", "zsh"]
            )
        )
    }

    func testItemMetadataInspectionUsesOperationAwareResourceHeading() {
        let viewModel = ApprovalRequestViewModel(
            request: Self.itemDescribeRequest,
            now: Date(timeIntervalSince1970: Self.viewModelNow)
        )
        let inspection: String = viewModel.requestInspectionText

        XCTAssertTrue(inspection.contains("Item metadata:"))
        XCTAssertFalse(inspection.contains("Secrets:"))
        XCTAssertTrue(inspection.contains("EXAMPLE_TOKEN [Account: Work] -> op://Example Vault/Example Item/token"))
        XCTAssertFalse(inspection.contains(Self.canarySecretValue))
    }

    func testSessionInspectionIncludesBindingProcessMetadata() {
        let viewModel = ApprovalRequestViewModel(
            request: Self.sessionCreateRequest,
            now: Date(timeIntervalSince1970: Self.viewModelNow)
        )
        let inspection: String = viewModel.requestInspectionText

        XCTAssertEqual(viewModel.sessionBindingSummary, "zsh pid=501")
        XCTAssertTrue(inspection.contains("Session binding:"))
        XCTAssertTrue(inspection.contains("Mode: ancestor_name"))
        XCTAssertTrue(inspection.contains("Ancestor names: Codex, zsh"))
        XCTAssertTrue(inspection.contains("Matched ancestor name: zsh"))
        XCTAssertTrue(inspection.contains("Ancestor depth: 1"))
        XCTAssertTrue(inspection.contains("Bound process: zsh pid=501 ppid=1 path=/bin/zsh"))
        let creatorLine = "Creator process: agent-secret pid=502 " +
            "path=/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret"
        XCTAssertTrue(inspection.contains(creatorLine))
        XCTAssertFalse(inspection.contains(Self.canarySecretValue))
    }
}
