@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    final class ApprovalRequestPanelLayoutTests: XCTestCase {
        private static let fixedNow = Date(timeIntervalSince1970: 1_800_000_000)
        private static let panelHeight: CGFloat = 660
        private static let panelWidth: CGFloat = 832

        private static func manyVaultGroupRequest(groupCount: Int) -> ApprovalRequest {
            let secrets = (1 ... groupCount).map { index in
                RequestedSecret(
                    alias: "SERVICE_\(index)_TOKEN",
                    ref: "op://Vault \(index)/Service/token",
                    account: "Account \(index)"
                )
            }
            return ApprovalRequest(
                requestID: "req_many_groups",
                nonce: "nonce_many_groups",
                reason: "Run a release workflow that needs many scoped credentials",
                command: ["/usr/bin/env", "agent-secret", "exec", "--", "make", "release"],
                cwd: "/tmp/project",
                expiresAt: fixedNow.addingTimeInterval(120),
                secrets: secrets,
                resolvedExecutable: "/usr/bin/env"
            )
        }

        @MainActor
        func testManyVaultGroupsStayInsideFixedApprovalPanelHeight() {
            let request = Self.manyVaultGroupRequest(groupCount: 32)
            let host = NSHostingView(
                rootView: ApprovalRequestPanelView(request: request, now: Self.fixedNow) { _ in
                    /* No decision action needed. */
                }
            )
            host.frame = NSRect(
                origin: .zero,
                size: NSSize(width: Self.panelWidth, height: Self.panelHeight)
            )
            host.layoutSubtreeIfNeeded()

            XCTAssertLessThanOrEqual(host.fittingSize.height, Self.panelHeight)
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }
#endif
