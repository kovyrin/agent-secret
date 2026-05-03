import Foundation

/// One requested secret prepared for display without secret values.
public struct RequestedSecretRowViewModel: Equatable, Sendable {
    private static let opReferencePrefix: String = "op://"

    public let alias: String
    public let ref: String
    public let account: String?
    public let accountLabel: String?
    public let vaultName: String
    public let vaultScopeName: String
    public let itemName: String?
    public let fieldName: String?
    public let symbolName: String

    public init(alias: String, ref: String, account: String? = nil) {
        let parts: [String] = Self.referenceParts(ref)
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
        vaultName = Self.sanitizedDisplayText(parts.first ?? "Unknown vault")
        if let account = self.account {
            vaultScopeName = "\(account) / \(vaultName)"
        } else {
            vaultScopeName = vaultName
        }
        itemName = parts.dropFirst().first.map(Self.sanitizedDisplayText)
        fieldName = parts.dropFirst().dropFirst().first.map(Self.sanitizedDisplayText)
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

    private static func sanitizedDisplayText(_ value: String) -> String {
        ApprovalDisplayTextSanitizer.sanitize(value)
    }
}
