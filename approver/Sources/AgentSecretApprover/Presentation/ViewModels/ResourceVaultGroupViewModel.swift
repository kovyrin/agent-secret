import Foundation

/// Keeps account-qualified vault grouping separate when vault names overlap.
public struct ResourceVaultGroupViewModel: Equatable, Sendable {
    public let vaultName: String
    public let resources: [RequestedResourceRowViewModel]

    public var resourceCount: Int {
        resources.count
    }

    public var countLabel: String {
        resourceCount == 1 ? "1 secret" : "\(resourceCount) secrets"
    }

    public var aliasSummary: String {
        resources.map(\.alias).joined(separator: ", ")
    }
}
