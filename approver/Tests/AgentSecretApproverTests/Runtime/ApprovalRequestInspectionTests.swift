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
}
