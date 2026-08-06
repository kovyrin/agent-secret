@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(AppKit)
    import AppKit

    final class AppKitApprovalPresenterTests: XCTestCase {
        private struct FixedScreenLockState: ScreenLockStateChecking {
            let locked: Bool

            func isScreenLocked() -> Bool {
                locked
            }
        }

        private static let fixedNow = Date(timeIntervalSince1970: 1_800_000_000)
        private static let wideScreenWidth: CGFloat = 720 * 2
        private static let tallScreenHeight: CGFloat = 600 * 2

        private static func approvalRequest(expiresAt: Date) -> ApprovalRequest {
            ApprovalRequest(
                requestID: "req_expired",
                nonce: "nonce_expired",
                reason: "Run a command",
                command: ["/usr/bin/env", "printenv", "TOKEN"],
                cwd: "/tmp/project",
                expiresAt: expiresAt,
                resources: [
                    RequestedResource(alias: "TOKEN", ref: "op://Example/Item/token", account: "Work")
                ],
                resolvedExecutable: "/usr/bin/env"
            )
        }

        @MainActor
        func testExpiredRequestPreflightsToTimeoutBeforeOpeningModal() {
            let request = Self.approvalRequest(expiresAt: Self.fixedNow)

            XCTAssertEqual(
                AppKitApprovalPresenter.preflightDecision(for: request, now: Self.fixedNow),
                ApprovalPresentationDecision(kind: .timeout)
            )
        }

        @MainActor
        func testUnexpiredRequestDoesNotPreflightToTimeout() {
            let request = Self.approvalRequest(expiresAt: Self.fixedNow.addingTimeInterval(0.001))

            XCTAssertNil(AppKitApprovalPresenter.preflightDecision(for: request, now: Self.fixedNow))
        }

        @MainActor
        func testLockedScreenPreflightsToDeniedWithoutOpeningModal() {
            let request = Self.approvalRequest(expiresAt: Self.fixedNow.addingTimeInterval(60))

            XCTAssertEqual(
                AppKitApprovalPresenter.preflightDecision(
                    for: request,
                    now: Self.fixedNow,
                    isScreenLocked: true
                ),
                ApprovalPresentationDecision(kind: .deny, denialReason: .computerLocked)
            )
        }

        @MainActor
        func testScreenLockCheckerCanBeInjected() {
            let presenter = AppKitApprovalPresenter(screenLockState: FixedScreenLockState(locked: true))
            let request = Self.approvalRequest(expiresAt: Self.fixedNow.addingTimeInterval(60))

            XCTAssertEqual(
                presenter.decide(for: request),
                ApprovalPresentationDecision(kind: .deny, denialReason: .computerLocked)
            )
        }

        @MainActor
        func testModalStopIsDeferredUntilModalRunLoopTurns() {
            let stopper = CountingModalStopper()
            let coordinator = AppKitModalDecisionCoordinator(stopper: stopper)

            coordinator.complete(with: .timeout)

            XCTAssertEqual(coordinator.decision, .timeout)
            XCTAssertEqual(stopper.stopCount, 0)

            let deadline = Date().addingTimeInterval(0.5)
            while stopper.stopCount == 0, Date() < deadline {
                _ = RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.01))
                _ = RunLoop.main.run(mode: .modalPanel, before: Date().addingTimeInterval(0.01))
            }

            XCTAssertEqual(stopper.stopCount, 1)
        }

        @MainActor
        func testApprovalPanelWindowCanBecomeKeyAndMain() {
            let window = ApprovalPanelWindow()

            XCTAssertTrue(window.canBecomeKey)
            XCTAssertTrue(window.canBecomeMain)
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
