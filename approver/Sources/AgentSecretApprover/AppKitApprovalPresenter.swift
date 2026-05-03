import Foundation

#if canImport(AppKit)
    import AppKit
#endif

/// Native macOS approval presenter.
public final class AppKitApprovalPresenter: ApprovalPresenter {
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
        private static func decideOnMain(for request: ApprovalRequest) -> ApprovalDecisionKind {
            if let preflightDecision: ApprovalDecisionKind = preflightDecision(for: request) {
                return preflightDecision
            }

            let app = NSApplication.shared
            Self.activate(app)
            let viewModel = ApprovalRequestViewModel(request: request)
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = viewModel.promptQuestion
            alert.informativeText = viewModel.renderedText
            alert.addButton(withTitle: "Deny")
            alert.addButton(withTitle: "Allow Once")
            alert.addButton(withTitle: "Allow Same Command Briefly")
            return decision(for: alert.runModal())
        }

        @MainActor
        static func preflightDecision(
            for request: ApprovalRequest,
            now: Date = Date()
        ) -> ApprovalDecisionKind? {
            ApprovalPromptExpiration(expiresAt: request.expiresAt).timeoutDecision(at: now)
        }

        static func decision(for response: NSApplication.ModalResponse) -> ApprovalDecisionKind {
            switch response {
            case .alertSecondButtonReturn:
                .approveOnce

            case .alertThirdButtonReturn:
                .approveReusable

            default:
                .deny
            }
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
