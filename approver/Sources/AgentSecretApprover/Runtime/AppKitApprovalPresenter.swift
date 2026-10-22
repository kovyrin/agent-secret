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

        private static let panelOrigin: CGFloat = 0

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

        static func fittedPanelSize(ideal: CGSize, visibleFrame: NSRect?) -> CGSize {
            guard let visibleFrame else {
                return ideal
            }
            let margin = ApprovalPanelLayout.screenMargin
            return CGSize(
                width: min(ideal.width, max(0, visibleFrame.width - margin)),
                height: min(ideal.height, max(0, visibleFrame.height - margin))
            )
        }

        @MainActor
        static func initialPanelSize(for request: ApprovalRequest, visibleFrame: NSRect?) -> CGSize {
            let available = fittedPanelSize(ideal: ApprovalPanelLayout.preferredSize, visibleFrame: visibleFrame)
            let hostingView = NSHostingView(rootView: ApprovalRequestPanelView(
                request: request,
                size: available,
                measuring: true
            ) { _ in
                // Measurement cannot submit a decision.
            })
            hostingView.layoutSubtreeIfNeeded()
            return fittedPanelSize(
                ideal: CGSize(width: available.width, height: hostingView.fittingSize.height),
                visibleFrame: visibleFrame
            )
        }

        @MainActor
        static func prepareWindowHostingView(_ hostingView: NSHostingView<some View>) {
            // Only the presenter may change geometry; disclosures and clock ticks scroll in place.
            hostingView.sizingOptions = []
        }

        @MainActor
        private static func makePanelWindow(size: CGSize) -> ApprovalPanelWindow {
            let window = ApprovalPanelWindow(
                contentRect: NSRect(
                    x: panelOrigin,
                    y: panelOrigin,
                    width: size.width,
                    height: size.height
                ),
                styleMask: [.borderless],
                backing: .buffered,
                defer: false
            )
            window.isOpaque = false
            window.backgroundColor = .clear
            window.hasShadow = false
            window.isMovableByWindowBackground = true
            return window
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
            let visibleFrame = (NSScreen.main ?? NSScreen.screens.first)?.visibleFrame
            let size = Self.initialPanelSize(for: request, visibleFrame: visibleFrame)
            let window = Self.makePanelWindow(size: size)
            let hostingView = NSHostingView(
                rootView: ApprovalRequestPanelView(
                    request: request,
                    size: size
                ) { selectedDecision in
                    logger.record("approval_modal_decision_selected", requestID: request.requestID)
                    coordinator.complete(with: selectedDecision)
                }
            )
            Self.prepareWindowHostingView(hostingView)
            window.contentView = hostingView
            activeWindow = window

            Self.bringForward(window)
            logger.record("approval_modal_presented", requestID: request.requestID)
            _ = app.runModal(for: window)
            logger.record("approval_modal_returned", requestID: request.requestID)
            activeWindow = nil
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
