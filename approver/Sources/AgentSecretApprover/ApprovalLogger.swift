import Foundation

/// Records non-secret approval lifecycle diagnostics.
public protocol ApprovalLogger {
    /// Records a metadata-only event for troubleshooting.
    func record(_ event: String, requestID: String?)
}
