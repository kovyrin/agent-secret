import Foundation

/// Raw metadata is the identity; sanitized labels must never merge distinct scopes.
struct ResourceScopeIdentity: Hashable {
    let provider: String
    let account: String
    let source: String
    let tokenAlias: String

    var label: String {
        let scope = provider == "1Password" ? (account.isEmpty ? "Desktop default account" : account)
            : (source.isEmpty ? "Default source" : source)
        return ApprovalDisplayTextSanitizer.sanitize(scope)
    }

    init(_ resource: RequestedResource) {
        provider = resource.ref.hasPrefix("bws://") ? "Bitwarden Secrets Manager" : "1Password"
        account = resource.account
        source = resource.source
        tokenAlias = resource.bitwardenTokenAlias
    }
}
