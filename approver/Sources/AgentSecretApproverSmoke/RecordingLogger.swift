import AgentSecretApprover
import Foundation

internal final class RecordingLogger: ApprovalLogger {
    internal private(set) var events: [String] = []

    internal func record(_ event: String, requestID: String?) {
        events.append("\(event):\(requestID ?? "none")")
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
