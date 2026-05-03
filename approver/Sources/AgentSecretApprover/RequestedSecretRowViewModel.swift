import Foundation

/// One requested secret prepared for display without secret values.
public struct RequestedSecretRowViewModel: Equatable, Sendable {
    /// Environment alias requested by the command.
    public let alias: String
    /// Backing 1Password reference.
    public let ref: String
    /// 1Password account scope for this reference, when available.
    public let account: String?
    /// Visible account scope label.
    public let accountLabel: String?

    /// Creates a display-only secret row.
    public init(alias: String, ref: String, account: String? = nil) {
        let normalizedAccount: String?
        if let account {
            let trimmedAccount = account.trimmingCharacters(in: .whitespacesAndNewlines)
            normalizedAccount = trimmedAccount.isEmpty ? nil : trimmedAccount
        } else {
            normalizedAccount = nil
        }
        self.alias = Self.sanitizedDisplayText(alias)
        self.ref = Self.sanitizedDisplayText(ref)
        self.account = normalizedAccount.map(Self.sanitizedDisplayText)
        accountLabel = self.account.map { account in "Account: \(account)" }
    }

    private static func sanitizedDisplayText(_ value: String) -> String {
        ApprovalDisplayTextSanitizer.sanitize(value)
    }
}
