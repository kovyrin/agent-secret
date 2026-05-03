import Foundation

#if canImport(AppKit)
    @MainActor
    final class AppKitModalDecisionCoordinator {
        private static let modalStopRunLoopModes: [RunLoop.Mode] = [
            .default,
            .modalPanel
        ]

        private let stopper: NSObject & AppKitModalStopping

        private(set) var decision: ApprovalDecisionKind = .deny

        init(stopper: NSObject & AppKitModalStopping) {
            self.stopper = stopper
        }

        func complete(with selectedDecision: ApprovalDecisionKind) {
            decision = selectedDecision
            stopper.perform(
                #selector(AppKitModalStopping.stopModal),
                with: nil,
                afterDelay: 0,
                inModes: Self.modalStopRunLoopModes
            )
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }
#endif
