import Foundation
import OSLog

public struct UnifiedApprovalLogger: ApprovalLogger {
    public let subsystem: String
    public let category: String

    public init(
        subsystem: String = "com.kovyrin.agent-secret.approver",
        category: String
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
