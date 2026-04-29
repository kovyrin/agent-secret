import Foundation

#if canImport(AppKit)
    import AppKit
#endif
#if canImport(SwiftUI)
    import SwiftUI
#endif

/// Native macOS approval presenter.
public final class AppKitApprovalPresenter: ApprovalPresenter {
    #if canImport(AppKit)
        private static let panelHeight: CGFloat = 660
        private static let panelOrigin: CGFloat = 0
        private static let panelWidth: CGFloat = 640
    #endif

    /// Creates an AppKit-backed presenter.
    public init() {
        /* No dependencies to initialize. */
    }

    #if canImport(AppKit)
        @MainActor
        private static func activate(_ app: NSApplication) {
            app.setActivationPolicy(.regular)
            app.unhide(nil)
            NSRunningApplication.current.activate(options: [.activateAllWindows])
            app.requestUserAttention(.criticalRequest)
        }

        @MainActor
        private static func bringForward(_ window: NSWindow) {
            window.level = .modalPanel
            window.collectionBehavior = [
                .canJoinAllSpaces,
                .fullScreenAuxiliary
            ]
            window.center()
            window.makeKeyAndOrderFront(nil)
            window.orderFrontRegardless()
            NSRunningApplication.current.activate(options: [.activateAllWindows])
        }

        @MainActor
        private static func decideOnMain(for request: ApprovalRequest) -> ApprovalDecisionKind {
            let app = NSApplication.shared
            Self.activate(app)
            let viewModel = ApprovalRequestViewModel(request: request)
            var decision: ApprovalDecisionKind = .deny
            let window = NSPanel(
                contentRect: NSRect(
                    x: Self.panelOrigin,
                    y: Self.panelOrigin,
                    width: Self.panelWidth,
                    height: Self.panelHeight
                ),
                styleMask: [.borderless],
                backing: .buffered,
                defer: false
            )
            window.isOpaque = false
            window.backgroundColor = .clear
            window.hasShadow = false
            window.isMovableByWindowBackground = true
            window.contentView = NSHostingView(
                rootView: ApprovalRequestPanelView(viewModel: viewModel) { selectedDecision in
                    decision = selectedDecision
                    app.stopModal()
                }
            )

            Self.bringForward(window)
            _ = app.runModal(for: window)
            window.close()
            return decision
        }
    #endif

    /// Presents the request and returns the operator decision.
    public func decide(for request: ApprovalRequest) -> ApprovalDecisionKind {
        #if canImport(AppKit)
            MainActor.assumeIsolated {
                Self.decideOnMain(for: request)
            }
        #else
            .timeout
        #endif
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
