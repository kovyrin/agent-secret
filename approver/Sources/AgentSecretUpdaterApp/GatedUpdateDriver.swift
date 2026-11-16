import AppKit
import Sparkle

/// Intercept the Install reply before Sparkle starts a cycle that can install on quit.
@MainActor
final class GatedUpdateDriver: SPUStandardUserDriver {
    var authorizeInstallation: (SUAppcastItem) async -> Bool = { _ in false }
    var abandonDownload: (() -> Void)?
    private var forwardedInstall = false
    private var startedExtraction = false
    private var pendingDecision: Task<Void, Never>?

    override func showUpdateFound(
        with appcastItem: SUAppcastItem,
        state: SPUUserUpdateState,
        reply: @escaping (SPUUserUpdateChoice) -> Void
    ) {
        super.showUpdateFound(with: appcastItem, state: state) { [weak self] choice in
            guard choice == .install, let self else {
                reply(choice == .install ? .dismiss : choice)
                return
            }
            guard state.stage != .installing else {
                reply(.skip)
                return
            }
            pendingDecision = Task {
                let admitted = await authorizeInstallation(appcastItem)
                guard !Task.isCancelled else {
                    return
                }
                pendingDecision = nil
                forwardedInstall = admitted
                reply(admitted ? .install : .dismiss)
            }
        }
    }

    override func showDownloadDidStartExtractingUpdate() {
        startedExtraction = true
        super.showDownloadDidStartExtractingUpdate()
    }

    override func dismissUpdateInstallation() {
        pendingDecision?.cancel()
        pendingDecision = nil
        if forwardedInstall, !startedExtraction {
            abandonDownload?()
        }
        forwardedInstall = false
        startedExtraction = false
        super.dismissUpdateInstallation()
    }
}
