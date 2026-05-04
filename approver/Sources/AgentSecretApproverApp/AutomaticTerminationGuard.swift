import Foundation

final class AutomaticTerminationGuard {
    private let reason: String
    private var isActive: Bool = true

    init(reason: String) {
        self.reason = reason
        ProcessInfo.processInfo.disableAutomaticTermination(reason)
    }

    func invalidate() {
        guard isActive else {
            return
        }
        isActive = false
        ProcessInfo.processInfo.enableAutomaticTermination(reason)
    }
}
