import Foundation

/// Keeps account-qualified vault grouping separate when vault names overlap.
public struct SecretVaultGroupViewModel: Equatable, Sendable {
    public let vaultName: String
    public let secrets: [RequestedSecretRowViewModel]

    public var secretCount: Int {
        secrets.count
    }

    public var countLabel: String {
        secretCount == 1 ? "1 secret" : "\(secretCount) secrets"
    }

    public var aliasSummary: String {
        secrets.map(\.alias).joined(separator: ", ")
    }
}
