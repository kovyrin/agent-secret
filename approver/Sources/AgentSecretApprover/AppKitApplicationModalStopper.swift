import Foundation

#if canImport(AppKit)
    import AppKit

    @MainActor
    final class AppKitApplicationModalStopper: NSObject, AppKitModalStopping {
        func stopModal() {
            NSApplication.shared.stopModal()
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }
#endif
