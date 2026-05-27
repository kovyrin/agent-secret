import Foundation

/// One Google consent item shown before Agent Secret opens the OAuth page.
public struct GCPOAuthConsentItem: Equatable, Identifiable, Sendable {
    public let id: String
    public let title: String
    public let detail: String

    /// Creates a value-only consent row for display and tests.
    public init(id: String, title: String, detail: String) {
        self.id = id
        self.title = title
        self.detail = detail
    }
}
