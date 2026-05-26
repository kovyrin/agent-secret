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
        detail: """
        Google's OpenID Connect label. Agent Secret uses it to bind the local account alias to the Google account \
        you select.
        """
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
        Required by Google so Agent Secret can call IAMCredentials to mint short-lived service-account tokens.
        """
    )

    /// Explains the Google IAM scope without overstating what OAuth grants by itself.
    public static let meaningText = """
    Approving this OAuth grant does not create service accounts, grant roles, or bypass Google IAM. Agent Secret can \
    only use IAM permissions that the selected Google account already has.
    """

    /// Warns operators away from broad admin accounts for bootstrap login.
    public static let adminRiskText = """
    If this Google account is Owner, IAM Admin, or Service Account Admin, this grant lets Agent Secret use those \
    existing permissions while the bootstrap credential remains configured. Prefer a bootstrap account that only has \
    Service Account Token Creator on the exact service accounts Agent Secret should use.
    """

    /// Explains the repeated open button behavior for users with multiple browser profiles.
    public static let retryText = """
    If Google opens in the wrong Chrome profile, switch to the correct Chrome window or profile, then click \
    Open Google Login again.
    """

    /// Returns consent rows for the OAuth scopes configured on the daemon.
    public static func consentItems(for scopes: [String]) -> [GCPOAuthConsentItem] {
        let normalizedScopes = scopes.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard !normalizedScopes.isEmpty else {
            return defaultConsentItems
        }
        return normalizedScopes.map { scope in
            switch scope {
            case "https://www.googleapis.com/auth/iam":
                iamConsentItem

            case "https://www.googleapis.com/auth/userinfo.email":
                emailConsentItem

            case "openid":
                openIDConsentItem

            default:
                GCPOAuthConsentItem(
                    id: scope,
                    title: "OAuth scope: \(scope)",
                    detail: "Agent Secret will ask Google for this configured OAuth scope."
                )
            }
        }
    }
}
