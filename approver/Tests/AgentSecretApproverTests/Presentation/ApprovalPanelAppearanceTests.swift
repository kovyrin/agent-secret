@testable import AgentSecretApprover
import XCTest

#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    final class ApprovalPanelAppearanceTests: XCTestCase {
        @MainActor
        func testProductionWindowHasNativeShadowAndTransparentCorners() {
            let window = AppKitApprovalPresenter.makePanelWindow(size: ApprovalPanelLayout.preferredSize)
            defer { window.close() }

            XCTAssertTrue(window.hasShadow)
            XCTAssertFalse(window.isOpaque)
            XCTAssertEqual(window.backgroundColor, .clear)
        }

        @MainActor
        func testLightSurfacesAreBrightOpaqueAndOnlySubtlySeparated() throws {
            for appearance in [NSAppearance.Name.aqua, .accessibilityHighContrastAqua] {
                let surface = try resolved(ApprovalPanelTheme.surface, appearance: appearance)
                let sidebar = try resolved(ApprovalPanelTheme.sunken, appearance: appearance)

                XCTAssertGreaterThan(surface.whiteComponent, 0.96)
                XCTAssertGreaterThan(sidebar.whiteComponent, 0.90)
                XCTAssertEqual(sidebar.alphaComponent, 1, accuracy: 0.001)
                XCTAssertGreaterThan(surface.whiteComponent, sidebar.whiteComponent)
                XCTAssertLessThan(surface.whiteComponent - sidebar.whiteComponent, 0.08)
            }
        }

        @MainActor
        func testDarkSurfacesRemainDarkAndOpaque() throws {
            for appearance in [NSAppearance.Name.darkAqua, .accessibilityHighContrastDarkAqua] {
                for color in [ApprovalPanelTheme.surface, ApprovalPanelTheme.sunken] {
                    let resolved = try resolved(color, appearance: appearance)
                    XCTAssertLessThan(resolved.whiteComponent, 0.30)
                    XCTAssertEqual(resolved.alphaComponent, 1, accuracy: 0.001)
                }
            }
        }

        @MainActor
        private func resolved(_ color: Color, appearance name: NSAppearance.Name) throws -> NSColor {
            let appearance = try XCTUnwrap(NSAppearance(named: name))
            var result: NSColor?
            appearance.performAsCurrentDrawingAppearance {
                result = NSColor(color).usingColorSpace(.genericGamma22Gray)
            }
            return try XCTUnwrap(result)
        }
    }
#endif
