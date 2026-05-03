@testable import AgentSecretApprover
import Foundation

#if canImport(AppKit)
    @MainActor
    final class CountingModalStopper: NSObject, AppKitModalStopping {
        private(set) var stopCount = 0

        func stopModal() {
            stopCount += 1
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }
#endif
