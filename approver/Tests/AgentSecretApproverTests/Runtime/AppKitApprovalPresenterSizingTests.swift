@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(AppKit)
    import AppKit
    import SwiftUI

    final class AppKitApprovalPresenterSizingTests: XCTestCase {
        private func request() throws -> ApprovalRequest {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            var request = try decoder.decode(
                ApprovalRequest.self, from: ApprovalProtocolFixture.data("approval_request")
            )
            request.expiresAt = Date().addingTimeInterval(120)
            return request
        }

        @MainActor
        func testWidthAndHeightAreBoundedToVisibleFrameWithMargin() {
            let fitted = AppKitApprovalPresenter.fittedPanelSize(
                ideal: ApprovalPanelLayout.preferredSize,
                visibleFrame: NSRect(x: 100, y: 200, width: 760, height: 600)
            )
            XCTAssertEqual(fitted, CGSize(width: 728, height: 568))
            XCTAssertLessThan(fitted.width - ApprovalPanelLayout.outerPadding * 2, 800)
            XCTAssertEqual(
                AppKitApprovalPresenter.fittedPanelSize(ideal: fitted, visibleFrame: nil), fitted
            )
        }

        @MainActor
        func testInitialMeasurementUsesActualNarrowWidthAndFitsShortScreen() throws {
            let frame = NSRect(x: 0, y: 0, width: 760, height: 600)
            let size = try AppKitApprovalPresenter.initialPanelSize(for: request(), visibleFrame: frame)
            XCTAssertEqual(size.width, 728)
            XCTAssertLessThanOrEqual(size.height, 568)
            XCTAssertGreaterThan(size.height, 0)
        }

        @MainActor
        func testDisclosuresAndClockCannotChangeWindowFrame() throws {
            let request = try request()
            let size = AppKitApprovalPresenter.initialPanelSize(
                for: request, visibleFrame: NSRect(x: 0, y: 0, width: 720 * 2, height: 900)
            )
            let hostingView = NSHostingView(rootView: ApprovalRequestPanelView(request: request, size: size) { _ in
                // Measurement cannot submit a decision.
            })
            hostingView.frame = NSRect(origin: .zero, size: size)
            let window = ApprovalPanelWindow(
                contentRect: hostingView.frame, styleMask: [.borderless], backing: .buffered, defer: false
            )
            window.alphaValue = 0
            AppKitApprovalPresenter.prepareWindowHostingView(hostingView)
            window.contentView = hostingView
            window.orderFront(nil)
            let frame = window.frame
            defer {
                window.orderOut(nil)
                window.close()
            }
            hostingView.layoutSubtreeIfNeeded()
            let deadline = Date().addingTimeInterval(1.1)
            while Date() < deadline {
                _ = RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.01))
            }
            XCTAssertEqual(window.frame, frame)
            XCTAssertTrue(hostingView.sizingOptions.isEmpty)
        }
    }
#endif
