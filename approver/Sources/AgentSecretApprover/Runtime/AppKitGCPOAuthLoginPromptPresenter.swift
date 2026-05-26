import Foundation

#if canImport(AppKit)
    import AppKit
#endif
#if canImport(SwiftUI)
    import SwiftUI
#endif

/// Presents the local warning that precedes Google Cloud OAuth bootstrap login.
public enum AppKitGCPOAuthLoginPromptPresenter {
    #if canImport(AppKit) && canImport(SwiftUI)
        @MainActor
        private final class WindowDelegate: NSObject, NSWindowDelegate {
            func windowWillClose(_: Notification) {
                NSApplication.shared.stopModal()
            }
        }

        private static let windowOrigin: CGFloat = 0
        private static let windowWidth: CGFloat = 760
        private static let windowHeight: CGFloat = 650

        /// Runs the prompt until the operator cancels or the daemon ends the helper process.
        @preconcurrency
        @MainActor
        public static func run(prompt: GCPOAuthLoginPrompt) {
            let app = NSApplication.shared
            app.setActivationPolicy(.regular)
            app.unhide(nil)
            NSRunningApplication.current.activate(options: [.activateAllWindows])
            app.requestUserAttention(.criticalRequest)

            let window = ApprovalPanelWindow(
                contentRect: NSRect(
                    x: windowOrigin,
                    y: windowOrigin,
                    width: windowWidth,
                    height: windowHeight
                ),
                styleMask: [.titled, .closable],
                backing: .buffered,
                defer: false
            )
            let delegate = WindowDelegate()
            window.title = "Agent Secret Google Cloud Login"
            window.isReleasedWhenClosed = false
            window.delegate = delegate
            window.contentView = NSHostingView(
                rootView: GCPOAuthLoginPromptView(
                    prompt: prompt,
                    openGoogle: { NSWorkspace.shared.open(prompt.authorizationURL) },
                    cancel: {
                        NSApplication.shared.stopModal()
                    }
                )
            )
            window.center()
            window.makeKeyAndOrderFront(nil)
            window.orderFrontRegardless()
            NSRunningApplication.current.activate(options: [.activateAllWindows])
            withExtendedLifetime(delegate) {
                _ = app.runModal(for: window)
            }
            window.close()
        }
    #else
        /// Returns immediately on platforms that cannot present the AppKit login prompt.
        @preconcurrency
        @MainActor
        public static func run(prompt _: GCPOAuthLoginPrompt) {
            /* AppKit is required for the Google Cloud OAuth login prompt. */
        }
    #endif
}
