import Foundation
import OSLog

/// Approval logger backed by Apple Unified Logging.
public struct UnifiedApprovalLogger: ApprovalLogger {
    public let subsystem: String
    public let category: String

    public init(
        category: String,
        subsystem: String = "com.kovyrin.agent-secret.approver"
    ) {
        self.subsystem = subsystem
        self.category = category
    }

    public func record(_ event: String, requestID: String?) {
        let logger = Logger(subsystem: subsystem, category: category)
        logger.info(
            "event=\(event, privacy: .public) request_id=\(requestID ?? "none", privacy: .public)"
        )
    }
}
