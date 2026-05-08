import Foundation

/// Keeps account-qualified vault grouping separate when vault names overlap.
struct ResourceVaultGroupViewModel: Equatable {
    let vaultName: String
    let resources: [RequestedResourceRowViewModel]

    var resourceCount: Int {
        resources.count
    }

    var countLabel: String {
        resourceCount == 1 ? "1 secret" : "\(resourceCount) secrets"
    }

    var aliasSummary: String {
        resources.map(\.alias).joined(separator: ", ")
    }
}
