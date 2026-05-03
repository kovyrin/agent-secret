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
        private static let panelWidth: CGFloat = 832
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
            if let preflightDecision: ApprovalDecisionKind = preflightDecision(for: request) {
                return preflightDecision
            }

            let app = NSApplication.shared
            Self.activate(app)
            let coordinator = AppKitModalDecisionCoordinator(stopper: AppKitApplicationModalStopper())
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
                rootView: ApprovalRequestPanelView(request: request) { selectedDecision in
                    coordinator.complete(with: selectedDecision)
                }
            )

            Self.bringForward(window)
            _ = app.runModal(for: window)
            window.close()
            return coordinator.decision
        }

        @MainActor
        static func preflightDecision(
            for request: ApprovalRequest,
            now: Date = Date()
        ) -> ApprovalDecisionKind? {
            ApprovalPromptExpiration(expiresAt: request.expiresAt).timeoutDecision(at: now)
        }
    #endif

    /// Presents the request and returns the operator decision.
    @preconcurrency
    @MainActor
    public func decide(for request: ApprovalRequest) -> ApprovalDecisionKind {
        #if canImport(AppKit)
            Self.decideOnMain(for: request)
        #else
            .timeout
        #endif
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
