import Foundation

#if canImport(AppKit)
    import AppKit
#endif
#if canImport(SwiftUI)
    import SwiftUI
#endif

/// AppKit-backed presenter that surfaces prompts on the main actor and fails closed outside AppKit.
public final class AppKitApprovalPresenter: ApprovalPresenter {
    #if canImport(AppKit)
        private static let panelHeight: CGFloat = 720
        private static let panelOrigin: CGFloat = 0
        private static let panelWidth: CGFloat = 912

        private let screenLockState: ScreenLockStateChecking
        @MainActor private var activeWindow: NSWindow?
    #endif

    public init(screenLockState: ScreenLockStateChecking = CGSessionScreenLockStateChecker()) {
        #if canImport(AppKit)
            self.screenLockState = screenLockState
        #endif
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
        static func preflightDecision(
            for request: ApprovalRequest,
            now: Date = Date(),
            isScreenLocked: Bool = false
        ) -> ApprovalPresentationDecision? {
            if isScreenLocked {
                return ApprovalPresentationDecision(kind: .deny, denialReason: .computerLocked)
            }
            guard let timeoutDecision = ApprovalPromptExpiration(expiresAt: request.expiresAt)
                .timeoutDecision(at: now)
            else {
                return nil
            }
            return ApprovalPresentationDecision(kind: timeoutDecision)
        }

        @MainActor
        private func decideOnMain(for request: ApprovalRequest) -> ApprovalPresentationDecision {
            if let preflightDecision: ApprovalPresentationDecision = Self.preflightDecision(
                for: request,
                isScreenLocked: screenLockState.isScreenLocked()
            ) {
                return preflightDecision
            }

            let app = NSApplication.shared
            let logger = UnifiedApprovalLogger(category: "decisions")
            Self.activate(app)
            let coordinator = AppKitModalDecisionCoordinator(stopper: AppKitApplicationModalStopper())
            let window = ApprovalPanelWindow(
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
                    logger.record("approval_modal_decision_selected", requestID: request.requestID)
                    coordinator.complete(with: selectedDecision)
                }
            )
            activeWindow = window

            Self.bringForward(window)
            logger.record("approval_modal_presented", requestID: request.requestID)
            _ = app.runModal(for: window)
            logger.record("approval_modal_returned", requestID: request.requestID)
            return ApprovalPresentationDecision(kind: coordinator.decision)
        }
    #endif

    /// Keeps UI work on the main actor; non-AppKit builds return timeout instead of approving.
    @preconcurrency
    @MainActor
    public func decide(for request: ApprovalRequest) -> ApprovalPresentationDecision {
        #if canImport(AppKit)
            decideOnMain(for: request)
        #else
            ApprovalPresentationDecision(kind: .timeout)
        #endif
    }
}
