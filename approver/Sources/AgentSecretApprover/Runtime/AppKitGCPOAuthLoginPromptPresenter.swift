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
            private let app: NSApplication

            init(app: NSApplication) {
                self.app = app
            }

            func windowWillClose(_: Notification) {
                app.stop(nil)
            }
        }

        @MainActor
        private final class WindowHandle {
            weak var window: NSWindow?
        }

        private static let windowOrigin: CGFloat = 0
        private static let windowWidth: CGFloat = 760
        private static let windowHeight: CGFloat = 488
        private static let minWindowWidth: CGFloat = 720
        private static let minWindowHeight: CGFloat = 460

        /// Runs the prompt until the operator cancels or the daemon ends the helper process.
        @preconcurrency
        @MainActor
        public static func run(prompt: GCPOAuthLoginPrompt) {
            let app = NSApplication.shared
            app.setActivationPolicy(.regular)
            app.unhide(nil)

            let windowHandle = WindowHandle()
            let content = makeContentView(prompt: prompt, windowHandle: windowHandle)
            let delegate = WindowDelegate(app: app)
            let window = makeWindow(contentView: content.view, delegate: delegate)
            windowHandle.window = window

            window.center()
            window.makeKeyAndOrderFront(nil)
            window.orderFrontRegardless()
            app.activate(ignoringOtherApps: true)
            NSRunningApplication.current.activate(options: [.activateAllWindows])
            app.requestUserAttention(.criticalRequest)

            withExtendedLifetime((delegate, content.hostingView, windowHandle)) {
                app.run()
            }
        }

        @MainActor
        private static func makeContentView(
            prompt: GCPOAuthLoginPrompt,
            windowHandle: WindowHandle
        ) -> (view: NSView, hostingView: NSHostingView<GCPOAuthLoginPromptView>) {
            let hostingView = NSHostingView(
                rootView: GCPOAuthLoginPromptView(
                    prompt: prompt,
                    openGoogle: { NSWorkspace.shared.open(prompt.authorizationURL) },
                    cancel: {
                        windowHandle.window?.close()
                    }
                )
            )
            let contentView = NSView(
                frame: NSRect(
                    x: windowOrigin,
                    y: windowOrigin,
                    width: windowWidth,
                    height: windowHeight
                )
            )
            contentView.wantsLayer = true
            contentView.layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
            hostingView.translatesAutoresizingMaskIntoConstraints = false
            contentView.addSubview(hostingView)
            NSLayoutConstraint.activate([
                hostingView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
                hostingView.trailingAnchor.constraint(equalTo: contentView.trailingAnchor),
                hostingView.topAnchor.constraint(equalTo: contentView.topAnchor),
                hostingView.bottomAnchor.constraint(equalTo: contentView.bottomAnchor)
            ])
            return (contentView, hostingView)
        }

        @MainActor
        private static func makeWindow(contentView: NSView, delegate: NSWindowDelegate) -> NSWindow {
            let window = NSWindow(
                contentRect: NSRect(
                    x: windowOrigin,
                    y: windowOrigin,
                    width: windowWidth,
                    height: windowHeight
                ),
                styleMask: [.titled, .closable, .miniaturizable],
                backing: .buffered,
                defer: false
            )
            window.title = "Agent Secret Google Cloud Login"
            window.level = .modalPanel
            window.collectionBehavior = [
                .canJoinAllSpaces,
                .fullScreenAuxiliary
            ]
            window.minSize = NSSize(width: minWindowWidth, height: minWindowHeight)
            window.isReleasedWhenClosed = false
            window.backgroundColor = .windowBackgroundColor
            window.setContentSize(NSSize(width: windowWidth, height: windowHeight))
            window.contentView = contentView
            window.delegate = delegate
            return window
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
