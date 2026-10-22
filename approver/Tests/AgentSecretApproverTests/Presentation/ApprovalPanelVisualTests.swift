@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    final class ApprovalPanelVisualTests: XCTestCase {
        @MainActor
        func testCaptureSyntheticVariantsWhenRequested() throws {
            guard let path = ProcessInfo.processInfo.environment["AGENT_SECRET_UI_CAPTURE_DIR"] else {
                throw XCTSkip("Set AGENT_SECRET_UI_CAPTURE_DIR to capture native synthetic variants")
            }
            let directory = URL(fileURLWithPath: path)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            for variant in ApprovalVisualFixture.Variant.allCases {
                for dark in [false, true] {
                    let harness = try NativeApprovalHarness(request: ApprovalVisualFixture.request(variant), dark: dark)
                    defer { harness.close() }
                    let name = "v\(variant.rawValue)-\(dark ? "dark" : "light").png"
                    try harness.capture(to: directory.appendingPathComponent(name))
                }
            }
        }

        @MainActor
        func testResourceAndDetailsRowsExposeFullWidthButtons() throws {
            guard ProcessInfo.processInfo.environment["AGENT_SECRET_NATIVE_UI_TESTS"] == "1" else {
                throw XCTSkip("Native accessibility checks are opt-in")
            }
            let harness = try NativeApprovalHarness(request: ApprovalVisualFixture.request(.single), dark: true)
            defer { harness.close() }
            let buttons = harness.elements.filter { $0.accessibilityRole() == .button }
            let resourceButton = buttons.first { $0.accessibilityLabel()?.contains("EXAMPLE_TOKEN") == true }
            guard let disclosure = resourceButton else {
                throw XCTSkip("Native accessibility tree unavailable in this test process")
            }
            XCTAssertGreaterThan(disclosure.accessibilityFrame().width, 350)
            XCTAssertTrue(disclosure.accessibilityPerformPress())
            harness.settle()
            XCTAssertTrue(harness.elements.contains { element in
                element.accessibilityValue() as? String == "op://Example Vault/Example Item/token"
            })
        }

        @MainActor
        func testCaptureDeadlineAndLegacyStatesWhenRequested() throws {
            guard let path = ProcessInfo.processInfo.environment["AGENT_SECRET_UI_CAPTURE_DIR"] else {
                throw XCTSkip("Set AGENT_SECRET_UI_CAPTURE_DIR to capture native edge states")
            }
            let directory = URL(fileURLWithPath: path)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            for seconds in [60, 15, 30] {
                var request = try ApprovalVisualFixture.request(.single)
                request.expiresAt = Date().addingTimeInterval(TimeInterval(seconds))
                let harness = NativeApprovalHarness(request: request, dark: true)
                defer { harness.close() }
                try harness.capture(to: directory.appendingPathComponent("remaining-\(seconds).png"))
            }
            var request = try ApprovalVisualFixture.request(.session)
            request.requestTTLSeconds = nil
            request.sessionMaxReads = nil
            let harness = NativeApprovalHarness(request: request, dark: false)
            defer { harness.close() }
            try harness.capture(to: directory.appendingPathComponent("legacy-session.png"))
        }

        @MainActor
        func testCaptureConstrainedLongContentWhenRequested() throws {
            guard let path = ProcessInfo.processInfo.environment["AGENT_SECRET_UI_CAPTURE_DIR"] else {
                throw XCTSkip("Set AGENT_SECRET_UI_CAPTURE_DIR to capture constrained native layout")
            }
            try FileManager.default.createDirectory(
                at: URL(fileURLWithPath: path),
                withIntermediateDirectories: true
            )
            var request = try ApprovalVisualFixture.request(.highScope)
            request.reason = String(repeating: "Review the synthetic deployment configuration. ", count: 30)
            request.command.append(String(repeating: "example-long-argument-", count: 30))
            let frame = NSRect(x: 0, y: 0, width: 760, height: 600)
            let harness = NativeApprovalHarness(
                request: request,
                dark: true,
                visibleFrame: frame
            )
            defer { harness.close() }
            XCTAssertLessThanOrEqual(harness.window.frame.width, frame.width)
            XCTAssertLessThanOrEqual(harness.window.frame.height, frame.height)
            let url = URL(fileURLWithPath: path).appendingPathComponent("constrained-long-content.png")
            try harness.capture(to: url)
        }
    }
#endif
