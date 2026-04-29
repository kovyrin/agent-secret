import AgentSecretApprover
import Foundation

final class RecordingLogger: ApprovalLogger {
    private(set) var events: [String] = []

    func record(_ event: String, requestID: String?) {
        events.append("\(event):\(requestID ?? "none")")
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
