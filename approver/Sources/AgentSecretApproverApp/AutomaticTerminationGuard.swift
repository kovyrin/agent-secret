import Foundation

final class AutomaticTerminationGuard {
    private let reason: String
    private let activity: any NSObjectProtocol
    private var isActive: Bool = true

    init(reason: String) {
        self.reason = reason
        ProcessInfo.processInfo.automaticTerminationSupportEnabled = true
        ProcessInfo.processInfo.disableAutomaticTermination(reason)
        ProcessInfo.processInfo.disableSuddenTermination()
        activity = ProcessInfo.processInfo.beginActivity(
            options: [.userInitiated],
            reason: reason
        )
    }

    func invalidate() {
        guard isActive else {
            return
        }
        isActive = false
        ProcessInfo.processInfo.endActivity(activity)
        ProcessInfo.processInfo.enableSuddenTermination()
        ProcessInfo.processInfo.enableAutomaticTermination(reason)
    }
}
