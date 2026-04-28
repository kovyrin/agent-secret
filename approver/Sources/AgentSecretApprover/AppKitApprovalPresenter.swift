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
        let app: NSApplication = NSApplication.shared
        Self.activate(app)
        let viewModel: ApprovalRequestViewModel = ApprovalRequestViewModel(request: request)

        let alert: NSAlert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = viewModel.title
        alert.informativeText = viewModel.renderedText
        alert.addButton(withTitle: "Approve once")
        alert.addButton(withTitle: viewModel.allowReusableTitle)
        alert.addButton(withTitle: "Deny")

        Self.bringForward(alert.window)

        switch alert.runModal() {
        case .alertFirstButtonReturn:
            return .approveOnce

        case .alertSecondButtonReturn:
            return .approveReusable

        default:
            return .deny
        }
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
