@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(AppKit) && canImport(SwiftUI)
    import AppKit
    import SwiftUI

    /// Captures production SwiftUI views drawn by AppKit, without screen-recording permission.
    @MainActor
    final class NativeApprovalHarness {
        private static let settleInterval: TimeInterval = 0.05

        let host: NSHostingView<AnyView>
        let window: NSWindow

        var elements: [any NSAccessibilityProtocol] {
            Self.descendants(host)
        }

        init(
            request: ApprovalRequest,
            dark: Bool,
            visibleFrame: NSRect? = nil
        ) {
            let size = AppKitApprovalPresenter.initialPanelSize(for: request, visibleFrame: visibleFrame)
            host = NSHostingView(rootView: AnyView(
                ApprovalRequestPanelView(request: request, size: size) { _ in
                    // Isolated rendering never delivers secret access.
                }
                .environment(\.colorScheme, dark ? .dark : .light)
            ))
            window = AppKitApprovalPresenter.makePanelWindow(size: size)
            window.isReleasedWhenClosed = false
            window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            window.alphaValue = 0
            AppKitApprovalPresenter.prepareWindowHostingView(host)
            window.contentView = host
            window.orderFront(nil)
            settle()
        }

        private static func descendants(_ element: any NSAccessibilityProtocol) -> [any NSAccessibilityProtocol] {
            let children = (element.accessibilityChildren() ?? []).compactMap { $0 as? any NSAccessibilityProtocol }
            return children + children.flatMap { descendants($0) }
        }

        func close() {
            window.orderOut(nil)
            window.close()
        }

        func settle() {
            host.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date().addingTimeInterval(Self.settleInterval))
        }

        func capture(to url: URL) throws {
            settle()
            let bitmap = try XCTUnwrap(host.bitmapImageRepForCachingDisplay(in: host.bounds))
            host.cacheDisplay(in: host.bounds, to: bitmap)
            let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
            try png.write(to: url)
        }
    }
#endif
