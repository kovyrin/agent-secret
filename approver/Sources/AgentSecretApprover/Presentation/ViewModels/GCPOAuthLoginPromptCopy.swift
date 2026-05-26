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
        title: "Associate you with your personal info on Google",
        detail: "Google's OpenID Connect label. Agent Secret uses it to bind this login to the selected account."
    )

    private static let emailConsentItem = GCPOAuthConsentItem(
        id: "userinfo.email",
        title: "See your primary Google Account email address",
        detail: "Used to show and verify which Google account completed login."
    )

    private static let iamConsentItem = GCPOAuthConsentItem(
        id: "iam",
        title: "Manage your Identity and Access Management (IAM) Policies",
        detail: """
        Required so Agent Secret can call IAMCredentials and mint short-lived service-account tokens.
        """
    )

    /// Explains the Google IAM scope without overstating what OAuth grants by itself.
    public static let meaningText = """
    This grant does not create service accounts, assign roles, or bypass Google IAM. It only lets Agent Secret use \
    permissions the selected Google account already has.
    """

    /// Warns operators away from broad admin accounts for bootstrap login.
    public static let adminRiskText = """
    Avoid Owner, IAM Admin, and Service Account Admin for normal use. Grant Service Account Token Creator only on the \
    exact service accounts Agent Secret should impersonate.
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
