#if canImport(AppKit)
    import AppKit
    import Combine

    /// Geometry changes only when the available screen changes, never on content or clock updates.
    @MainActor
    final class ApprovalPanelScreenObserver: NSObject, NSWindowDelegate {
        private weak var window: NSWindow?
        private var lastFrame: NSRect?
        private let refit: (NSRect) -> Void
        private var screenChanges: AnyCancellable?

        init(window: NSWindow, refit: @escaping (NSRect) -> Void) {
            self.window = window
            lastFrame = window.screen?.visibleFrame
            self.refit = refit
            super.init()
            window.delegate = self
            screenChanges = NotificationCenter.default
                .publisher(for: NSApplication.didChangeScreenParametersNotification)
                .sink { [weak self] _ in
                    MainActor.assumeIsolated { self?.refresh() }
                }
        }

        func windowDidChangeScreen(_: Notification) {
            refresh()
        }

        private func refresh() {
            guard let frame = window?.screen?.visibleFrame, frame != lastFrame else {
                return
            }
            lastFrame = frame
            refit(frame)
        }
    }
#endif
