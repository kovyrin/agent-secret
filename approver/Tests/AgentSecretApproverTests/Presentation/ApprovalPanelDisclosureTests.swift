@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    final class ApprovalPanelDisclosureTests: XCTestCase {
        @MainActor
        func testFullLabelRowIsAnAccessibleButtonAndPressExpandsContent() throws {
            guard ProcessInfo.processInfo.environment["AGENT_SECRET_NATIVE_UI_TESTS"] == "1" else {
                throw XCTSkip("Native accessibility checks are opt-in")
            }
            var expanded = false
            let binding = Binding(get: { expanded }, set: { expanded = $0 })
            let view = DisclosureGroup("Inspect example scope", isExpanded: binding) {
                Text("Complete synthetic reference")
            }
            .disclosureGroupStyle(ApprovalPanelDisclosureStyle())
            .frame(width: 400)
            let host = NSHostingView(rootView: view)
            let window = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 400, height: 160),
                styleMask: [.borderless],
                backing: .buffered,
                defer: false
            )
            window.isReleasedWhenClosed = false
            window.contentView = host
            window.alphaValue = 1
            window.orderFront(nil)
            defer {
                window.orderOut(nil)
                window.close()
            }
            host.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
            let buttons = accessibilityElements(host).filter { $0.accessibilityRole() == .button }
            guard let button = buttons.first else {
                throw XCTSkip("Native accessibility tree is unavailable in this test process")
            }
            XCTAssertGreaterThanOrEqual(button.accessibilityFrame().width, 390)
            XCTAssertGreaterThanOrEqual(button.accessibilityFrame().height, 30)
            XCTAssertTrue(button.accessibilityPerformPress())
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
            XCTAssertTrue(expanded)
            XCTAssertTrue(button.accessibilityPerformPress())
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
            XCTAssertFalse(expanded)
        }

        @MainActor
        private func accessibilityElements(_ element: any NSAccessibilityProtocol) -> [any NSAccessibilityProtocol] {
            let children = (element.accessibilityChildren() ?? []).compactMap { $0 as? any NSAccessibilityProtocol }
            return children + children.flatMap { accessibilityElements($0) }
        }
    }
#endif
