import Foundation

/// Records non-secret approval lifecycle diagnostics.
public protocol ApprovalLogger {
    /// Event names and request IDs must be metadata-only and value-free.
    func record(_ event: String, requestID: String?)
}
