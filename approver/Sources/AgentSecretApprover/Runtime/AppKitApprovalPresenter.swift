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
        private typealias Metric = ApprovalPanelStyle.Metric

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

        static func panelHeight(visibleScreenHeight: CGFloat?) -> CGFloat {
            panelHeight(
                idealContentHeight: Metric.panelMinimumHeight,
                visibleScreenHeight: visibleScreenHeight
            )
        }

        static func panelHeight(idealContentHeight: CGFloat, visibleScreenHeight: CGFloat?) -> CGFloat {
            guard let visibleScreenHeight else {
                return Metric.panelMinimumHeight
            }

            let preferredHeight = max(Metric.panelMinimumHeight, idealContentHeight)
            return min(preferredHeight, maximumPanelHeight(visibleScreenHeight: visibleScreenHeight))
        }

        @MainActor
        static func initialPanelHeight(
            for request: ApprovalRequest,
            visibleScreenHeight: CGFloat?
        ) -> CGFloat {
            let maximumPanelHeight = maximumPanelHeight(visibleScreenHeight: visibleScreenHeight)
            let maximumScrollableContentHeight = scrollableContentHeight(
                forPanelHeight: maximumPanelHeight
            )
            let hostingView = NSHostingView(
                rootView: ApprovalRequestPanelView(
                    request: request,
                    maxScrollableContentHeight: maximumScrollableContentHeight
                ) { _ in
                    // This view is measured before presentation and cannot submit a decision.
                }
            )
            hostingView.layoutSubtreeIfNeeded()
            return panelHeight(
                idealContentHeight: hostingView.fittingSize.height,
                visibleScreenHeight: visibleScreenHeight
            )
        }

        @MainActor
        static func prepareWindowHostingView(
            _ hostingView: NSHostingView<some View>
        ) {
            // The presenter owns panel geometry; intrinsic-size propagation can resize a visible window.
            hostingView.sizingOptions = []
        }

        static func scrollableContentHeight(forPanelHeight panelHeight: CGFloat) -> CGFloat {
            max(
                Metric.zeroOffset,
                panelHeight - Metric.panelPinnedVerticalContentHeight
            )
        }

        static func idealPanelHeight(
            scrollContentHeight: CGFloat,
            pinnedContentHeight: CGFloat
        ) -> CGFloat {
            scrollContentHeight +
                pinnedContentHeight +
                Metric.sectionSpacing +
                (Metric.cardVerticalPadding * Metric.verticalEdgeCount) +
                (Metric.outerPadding * Metric.verticalEdgeCount)
        }

        static func resizedPanelFrame(
            currentFrame: NSRect,
            targetHeight: CGFloat,
            visibleFrame: NSRect
        ) -> NSRect {
            let height = min(targetHeight, visibleFrame.height)
            let centeredY = currentFrame.midY - (height / Metric.verticalEdgeCount)
            let minimumY = visibleFrame.minY
            let maximumY = visibleFrame.maxY - height
            let originY = min(max(centeredY, minimumY), maximumY)
            return NSRect(
                x: currentFrame.origin.x,
                y: originY,
                width: currentFrame.width,
                height: height
            )
        }

        private static func maximumPanelHeight(visibleScreenHeight: CGFloat?) -> CGFloat {
            guard let visibleScreenHeight else {
                return Metric.panelMinimumHeight
            }

            if visibleScreenHeight <= Metric.panelVisibleFrameVerticalMargin {
                return visibleScreenHeight
            }
            return visibleScreenHeight - Metric.panelVisibleFrameVerticalMargin
        }

        @MainActor
        private static func resize(
            _ window: NSWindow,
            to targetHeight: CGFloat,
            within visibleFrame: NSRect
        ) {
            let targetFrame = resizedPanelFrame(
                currentFrame: window.frame,
                targetHeight: targetHeight,
                visibleFrame: visibleFrame
            )
            guard abs(targetFrame.height - window.frame.height) > Metric.resizeTolerance else {
                return
            }
            window.setFrame(targetFrame, display: true, animate: true)
        }

        @MainActor
        private static func makePanelWindow(height: CGFloat) -> ApprovalPanelWindow {
            let window = ApprovalPanelWindow(
                contentRect: NSRect(
                    x: panelOrigin,
                    y: panelOrigin,
                    width: panelWidth,
                    height: height
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
            let visibleScreenHeight = visibleFrame?.height
            let maximumPanelHeight = Self.maximumPanelHeight(visibleScreenHeight: visibleScreenHeight)
            let panelHeight = Self.initialPanelHeight(
                for: request,
                visibleScreenHeight: visibleScreenHeight
            )
            let window = Self.makePanelWindow(height: panelHeight)
            let hostingView = NSHostingView(
                rootView: ApprovalRequestPanelView(
                    request: request,
                    maxScrollableContentHeight: Self.scrollableContentHeight(forPanelHeight: maximumPanelHeight),
                    contentHeightDidChange: { [weak window] idealContentHeight in
                        guard let window, let visibleFrame else {
                            return
                        }
                        let targetHeight = Self.panelHeight(
                            idealContentHeight: idealContentHeight,
                            visibleScreenHeight: visibleScreenHeight
                        )
                        Self.resize(window, to: targetHeight, within: visibleFrame)
                    },
                    decide: { selectedDecision in
                        logger.record("approval_modal_decision_selected", requestID: request.requestID)
                        coordinator.complete(with: selectedDecision)
                    }
                )
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
