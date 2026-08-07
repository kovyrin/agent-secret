@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(AppKit)
    import AppKit
    import SwiftUI

    final class AppKitApprovalPresenterSizingTests: XCTestCase {
        private static let fixedNow = Date(timeIntervalSince1970: 1_800_000_000)
        private static let wideScreenWidth: CGFloat = 720 * 2
        private static let tallScreenHeight: CGFloat = 600 * 2

        private static func tallApprovalRequest() -> ApprovalRequest {
            ApprovalRequest(
                requestID: "req_tall_panel",
                nonce: "nonce_tall_panel",
                reason: [
                    "Run a read-only release verification with configuration checks,",
                    "dependency health checks, and a final deployment-plan review",
                    "without allowing write operations."
                ].joined(separator: " "),
                command: ["agent-secret", "session", "create"],
                cwd: "/Users/example/projects/sample-service",
                expiresAt: fixedNow.addingTimeInterval(600),
                resources: (1 ... 3).map { index in
                    RequestedResource(
                        alias: "EXAMPLE_TOKEN_\(index)",
                        ref: "op://Example Vault \(index)/Example Item/token",
                        account: "Work"
                    )
                },
                resolvedExecutable: "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret",
                operation: .sessionCreate,
                allowsReusable: false,
                accessDurationSeconds: 300
            )
        }

        private static func visualSmokeApprovalRequest() -> ApprovalRequest {
            ApprovalRequest(
                requestID: "req_visual_smoke",
                nonce: "nonce_visual_smoke",
                reason: [
                    "Run a read-only release verification for the sample service, including configuration",
                    "checks, dependency health checks, and a final deployment-plan review without allowing",
                    "any write operations. The workflow records only non-secret verification metadata and",
                    "keeps the approved values in the bounded session."
                ].joined(separator: " "),
                command: ["agent-secret", "session", "create"],
                cwd: "/Users/example/projects/sample-service",
                expiresAt: fixedNow.addingTimeInterval(600),
                resources: [
                    RequestedResource(
                        alias: "DEPLOY_API_TOKEN",
                        ref: "op://Example Vault/Sample Service/DEPLOY_API_TOKEN",
                        account: "example.1password.com"
                    ),
                    RequestedResource(
                        alias: "OBSERVABILITY_API_TOKEN",
                        ref: "op://Example Vault/Observability/API_TOKEN",
                        account: "example.1password.com"
                    )
                ],
                resolvedExecutable: "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret",
                operation: .sessionCreate,
                allowsReusable: false,
                accessDurationSeconds: 300
            )
        }

        @MainActor
        func testPanelHeightFallsBackToMinimumWhenScreenHeightIsUnavailable() {
            XCTAssertEqual(AppKitApprovalPresenter.panelHeight(visibleScreenHeight: nil), 720)
        }

        @MainActor
        func testPanelHeightUsesIdealContentHeightWhenItFits() {
            XCTAssertEqual(
                AppKitApprovalPresenter.panelHeight(
                    idealContentHeight: 820,
                    visibleScreenHeight: 920
                ),
                820
            )
        }

        @MainActor
        func testPanelHeightUsesVisibleHeightWhenContentExceedsScreen() {
            XCTAssertEqual(
                AppKitApprovalPresenter.panelHeight(
                    idealContentHeight: 999,
                    visibleScreenHeight: 920
                ),
                888
            )
        }

        @MainActor
        func testPanelHeightCanGrowPastOldMaximumOnTallScreens() {
            XCTAssertEqual(
                AppKitApprovalPresenter.panelHeight(
                    idealContentHeight: 950,
                    visibleScreenHeight: 999
                ),
                950
            )
        }

        @MainActor
        func testPanelHeightFitsShortVisibleScreens() {
            XCTAssertEqual(
                AppKitApprovalPresenter.panelHeight(
                    idealContentHeight: 720,
                    visibleScreenHeight: 640
                ),
                608
            )
        }

        @MainActor
        func testScrollableContentHeightExpandsWithPanelHeight() {
            XCTAssertEqual(AppKitApprovalPresenter.scrollableContentHeight(forPanelHeight: 720), 520)
            XCTAssertEqual(AppKitApprovalPresenter.scrollableContentHeight(forPanelHeight: 900), 700)
        }

        @MainActor
        func testScrollableContentHeightStaysInsideShortPanels() {
            XCTAssertEqual(AppKitApprovalPresenter.scrollableContentHeight(forPanelHeight: 180), 0)
        }

        @MainActor
        func testIdealPanelHeightIncludesMeasuredRequestAndPinnedContent() {
            XCTAssertEqual(
                AppKitApprovalPresenter.idealPanelHeight(
                    scrollContentHeight: 540,
                    pinnedContentHeight: 110
                ),
                732
            )
        }

        @MainActor
        func testInitialPanelHeightMatchesTheFirstMeasuredContentHeight() {
            let visibleScreenHeight: CGFloat = 950
            let maximumPanelHeight: CGFloat = 918
            let hostingView = NSHostingView(
                rootView: ApprovalRequestPanelView(
                    request: Self.tallApprovalRequest(),
                    maxScrollableContentHeight: AppKitApprovalPresenter.scrollableContentHeight(
                        forPanelHeight: maximumPanelHeight
                    )
                ) { _ in
                    // The measurement view cannot submit a decision.
                }
            )
            hostingView.layoutSubtreeIfNeeded()
            let measuredPanelHeight = AppKitApprovalPresenter.panelHeight(
                idealContentHeight: hostingView.fittingSize.height,
                visibleScreenHeight: visibleScreenHeight
            )

            XCTAssertGreaterThan(measuredPanelHeight, 720)
            XCTAssertEqual(
                AppKitApprovalPresenter.initialPanelHeight(
                    for: Self.tallApprovalRequest(),
                    visibleScreenHeight: visibleScreenHeight
                ),
                measuredPanelHeight,
                accuracy: 0.5
            )
        }

        @MainActor
        func testInitialPanelHeightStaysStableAfterDelayedViewMeasurements() {
            let request = Self.visualSmokeApprovalRequest()
            let visibleScreenHeight: CGFloat = 950
            let maximumPanelHeight: CGFloat = 918
            let initialHeight = AppKitApprovalPresenter.initialPanelHeight(
                for: request,
                visibleScreenHeight: visibleScreenHeight
            )
            var measuredHeights: [CGFloat] = []
            let hostingView = NSHostingView(
                rootView: ApprovalRequestPanelView(
                    request: request,
                    maxScrollableContentHeight: AppKitApprovalPresenter.scrollableContentHeight(
                        forPanelHeight: maximumPanelHeight
                    ),
                    contentHeightDidChange: { measuredHeights.append($0) },
                    decide: { _ in
                        // The measurement view cannot submit a decision.
                    }
                )
            )
            hostingView.frame = NSRect(x: 0, y: 0, width: 912, height: initialHeight)
            let window = ApprovalPanelWindow(
                contentRect: hostingView.frame,
                styleMask: [.borderless],
                backing: .buffered,
                defer: false
            )
            window.alphaValue = 0
            AppKitApprovalPresenter.prepareWindowHostingView(hostingView)
            window.contentView = hostingView
            window.orderFront(nil)
            let presentedFrame = window.frame
            defer {
                window.orderOut(nil)
                window.close()
            }
            hostingView.layoutSubtreeIfNeeded()

            let deadline = Date().addingTimeInterval(2.2)
            while Date() < deadline {
                _ = RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.01))
            }
            XCTAssertFalse(measuredHeights.isEmpty)
            let firstMeasuredHeight = measuredHeights[0]
            XCTAssertTrue(
                measuredHeights.allSatisfy { abs($0 - firstMeasuredHeight) <= 0.5 },
                "content height changed after presentation: \(measuredHeights)"
            )
            XCTAssertEqual(window.frame, presentedFrame)
        }

        @MainActor
        func testResizedPanelFrameGrowsAroundItsCenter() {
            let current = NSRect(x: 100, y: 200, width: 912, height: 720)
            let visible = NSRect(
                x: 0,
                y: 0,
                width: Self.wideScreenWidth,
                height: Self.tallScreenHeight
            )

            XCTAssertEqual(
                AppKitApprovalPresenter.resizedPanelFrame(
                    currentFrame: current,
                    targetHeight: 820,
                    visibleFrame: visible
                ),
                NSRect(x: 100, y: 150, width: 912, height: 820)
            )
        }

        @MainActor
        func testResizedPanelFrameStaysInsideVisibleScreen() {
            let current = NSRect(x: 100, y: 20, width: 912, height: 720)
            let visible = NSRect(x: 0, y: 10, width: Self.wideScreenWidth, height: 900)

            XCTAssertEqual(
                AppKitApprovalPresenter.resizedPanelFrame(
                    currentFrame: current,
                    targetHeight: 880,
                    visibleFrame: visible
                ),
                NSRect(x: 100, y: 10, width: 912, height: 880)
            )
        }
    }
#endif
