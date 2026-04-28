import Foundation
import OSLog

/// Approval logger backed by Apple Unified Logging.
public struct UnifiedApprovalLogger: ApprovalLogger {
    /// Unified Logging subsystem.
    public let subsystem: String
    /// Unified Logging category.
    public let category: String

    /// Creates a value-free approval logger.
    public init(
        category: String,
        subsystem: String = "com.kovyrin.agent-secret.approver"
    ) {
        self.subsystem = subsystem
        self.category = category
    }

    /// Records a metadata-only approval event.
    public func record(_ event: String, requestID: String?) {
        let logger: Logger = Logger(subsystem: subsystem, category: category)
        logger.info(
            "event=\(event, privacy: .public) request_id=\(requestID ?? "none", privacy: .public)"
        )
    }
}
