import Foundation

/// One requested secret prepared for display without secret values.
public struct RequestedSecretRowViewModel: Equatable, Sendable {
    private static let opReferencePrefix: String = "op://"

    public let alias: String
    public let ref: String
    public let account: String
    public let accountLabel: String
    public let vaultName: String
    public let vaultScopeName: String
    public let itemName: String?
    public let fieldName: String?
    public let symbolName: String

    public init(alias: String, ref: String, account: String) {
        let parts: [String] = Self.referenceParts(ref)
        let normalizedAccount: String = account.trimmingCharacters(in: .whitespacesAndNewlines)
        self.alias = Self.sanitizedDisplayText(alias)
        self.ref = Self.sanitizedDisplayText(ref)
        self.account = Self.sanitizedDisplayText(normalizedAccount)
        accountLabel = "Account: \(self.account)"
        vaultName = Self.sanitizedDisplayText(parts.first ?? "Unknown vault")
        vaultScopeName = "\(self.account) / \(vaultName)"
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
