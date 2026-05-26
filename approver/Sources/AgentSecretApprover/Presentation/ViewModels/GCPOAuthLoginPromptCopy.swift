import Foundation

/// Shared text for the Google Cloud OAuth bootstrap login prompt.
public enum GCPOAuthLoginPromptCopy {
    /// Consent items that Google shows for the bundled desktop OAuth client.
    public static let defaultConsentItems: [GCPOAuthConsentItem] = [
        iamConsentItem,
        emailConsentItem,
        openIDConsentItem
    ]

    private static let openIDConsentItem = GCPOAuthConsentItem(
        id: "openid",
        title: "Account identity",
        detail: "OpenID Connect"
    )

    private static let emailConsentItem = GCPOAuthConsentItem(
        id: "userinfo.email",
        title: "Email address",
        detail: "Verify account"
    )

    private static let iamConsentItem = GCPOAuthConsentItem(
        id: "iam",
        title: "IAM policy scope",
        detail: """
        Shown by Google as "Manage IAM Policies"
        """
    )

    /// Explains the Google IAM scope without overstating what OAuth grants by itself.
    public static let meaningText = """
    This grant does not create service accounts, assign roles, or bypass IAM. Agent Secret can only use permissions \
    this Google account already has.
    """

    /// Warns operators away from broad admin accounts for bootstrap login.
    public static let adminRiskText = """
    Use a narrow bootstrap account: Token Creator only on the service accounts Agent Secret may impersonate.
    """

    /// Explains the repeated open button behavior for users with multiple browser profiles.
    public static let retryText = """
    If Google opens in the wrong Chrome profile, switch profiles and click Open Google again.
    """

    /// Returns consent rows for the OAuth scopes configured on the daemon.
    public static func consentItems(for scopes: [String]) -> [GCPOAuthConsentItem] {
        let normalizedScopes = scopes.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard !normalizedScopes.isEmpty else {
            return defaultConsentItems
        }
        let knownItems: [(scope: String, item: GCPOAuthConsentItem)] = [
            ("https://www.googleapis.com/auth/iam", iamConsentItem),
            ("https://www.googleapis.com/auth/userinfo.email", emailConsentItem),
            ("openid", openIDConsentItem)
        ]
        let knownScopes = Set(knownItems.map(\.scope))
        var items = knownItems.compactMap { scope, item in
            normalizedScopes.contains(scope) ? item : nil
        }
        items += normalizedScopes.compactMap { scope in
            guard !knownScopes.contains(scope) else {
                return nil
            }
            return unknownConsentItem(scope: scope)
        }
        return items
    }

    private static func unknownConsentItem(scope: String) -> GCPOAuthConsentItem {
        GCPOAuthConsentItem(
            id: scope,
            title: "OAuth scope: \(scope)",
            detail: "Agent Secret will ask Google for this configured OAuth scope."
        )
    }
}
