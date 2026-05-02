import Foundation

/// One requested secret prepared for display without secret values.
public struct RequestedSecretRowViewModel: Equatable, Sendable {
    private static let opReferencePrefix: String = "op://"

    /// Environment alias requested by the command.
    public let alias: String
    /// Backing 1Password reference.
    public let ref: String
    /// 1Password account scope for this reference, when available.
    public let account: String?
    /// Visible account scope label.
    public let accountLabel: String?
    /// Vault name parsed from an op reference when available.
    public let vaultName: String
    /// Account-qualified vault scope used for grouping.
    public let vaultScopeName: String
    /// Item name parsed from an op reference when available.
    public let itemName: String?
    /// Field name parsed from an op reference when available.
    public let fieldName: String?
    /// SF Symbol used for the secret row.
    public let symbolName: String

    /// Creates a display-only secret row.
    public init(alias: String, ref: String, account: String? = nil) {
        let parts: [String] = Self.referenceParts(ref)
        let normalizedAccount: String?
        if let account {
            let trimmedAccount = account.trimmingCharacters(in: .whitespacesAndNewlines)
            normalizedAccount = trimmedAccount.isEmpty ? nil : trimmedAccount
        } else {
            normalizedAccount = nil
        }
        self.alias = alias
        self.ref = ref
        self.account = normalizedAccount
        accountLabel = normalizedAccount.map { account in "Account: \(account)" }
        vaultName = parts.first ?? "Unknown vault"
        if let normalizedAccount {
            vaultScopeName = "\(normalizedAccount) / \(vaultName)"
        } else {
            vaultScopeName = vaultName
        }
        itemName = parts.dropFirst().first
        fieldName = parts.dropFirst().dropFirst().first
        symbolName = Self.symbolName(alias: alias, ref: ref)
    }

    private static func referenceParts(_ ref: String) -> [String] {
        guard ref.hasPrefix(opReferencePrefix) else {
            return []
        }
        return ref.dropFirst(opReferencePrefix.count)
            .split(separator: "/", omittingEmptySubsequences: false)
            .map(String.init)
    }

    private static func symbolName(alias: String, ref: String) -> String {
        let text = "\(alias) \(ref)".uppercased()
        if text.contains("PASSWORD") {
            return "lock"
        }
        if text.contains("USER") || text.contains("LOGIN") || text.contains("EMAIL") {
            return "person"
        }
        return "key"
    }
}
