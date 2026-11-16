import AppKit
import Sparkle

@MainActor
final class GentleUpdateDelegate: NSObject, SPUStandardUserDriverDelegate {
    var presentDeferredReminder: (() -> Void)?
    private let foregroundChanges: NotificationCenter
    private let approvalHasFocus: () -> Bool
    private var foregroundObserver: (any NSObjectProtocol)?

    /// An approval is a separate process with the outer app's bundle identifier.
    nonisolated var supportsGentleScheduledUpdateReminders: Bool {
        true
    }

    init(
        foregroundChanges: NotificationCenter = NSWorkspace.shared.notificationCenter,
        approvalHasFocus: @escaping () -> Bool = {
            NSWorkspace.shared.frontmostApplication?.bundleIdentifier == "com.kovyrin.agent-secret"
        }
    ) {
        self.foregroundChanges = foregroundChanges
        self.approvalHasFocus = approvalHasFocus
    }

    nonisolated func standardUserDriverShouldHandleShowingScheduledUpdate(
        _: SUAppcastItem, andInImmediateFocus _: Bool
    ) -> Bool {
        MainActor.assumeIsolated { !approvalHasFocus() }
    }

    nonisolated func standardUserDriverWillHandleShowingUpdate(
        _ standardDriverHandlesUpdate: Bool, forUpdate _: SUAppcastItem, state _: SPUUserUpdateState
    ) {
        if !standardDriverHandlesUpdate {
            MainActor.assumeIsolated { deferReminder() }
        }
    }

    nonisolated func standardUserDriverDidReceiveUserAttention(forUpdate _: SUAppcastItem) {
        MainActor.assumeIsolated { cancelReminder() }
    }

    nonisolated func standardUserDriverWillFinishUpdateSession() {
        MainActor.assumeIsolated { cancelReminder() }
    }

    func deferReminder() {
        guard foregroundObserver == nil else {
            return
        }
        foregroundObserver = foregroundChanges.addObserver(
            forName: NSWorkspace.didActivateApplicationNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.foregroundDidChange() }
        }
        foregroundDidChange()
    }

    private func foregroundDidChange() {
        guard foregroundObserver != nil, !approvalHasFocus() else {
            return
        }
        cancelReminder()
        presentDeferredReminder?()
    }

    private func cancelReminder() {
        if let foregroundObserver {
            foregroundChanges.removeObserver(foregroundObserver)
            self.foregroundObserver = nil
        }
    }
}
