import Foundation

/// Requested secrets grouped by their backing vault or account-qualified vault.
public struct SecretVaultGroupViewModel: Equatable, Sendable {
    /// Vault or account-qualified vault name shown in the grouped secret summary.
    public let vaultName: String
    /// Secrets requested from this vault.
    public let secrets: [RequestedSecretRowViewModel]

    /// Number of requested secrets in this vault.
    public var secretCount: Int {
        secrets.count
    }

    /// Human-readable count label.
    public var countLabel: String {
        secretCount == 1 ? "1 secret" : "\(secretCount) secrets"
    }

    /// Comma-separated aliases for the compact vault row.
    public var aliasSummary: String {
        secrets.map(\.alias).joined(separator: ", ")
    }
}
