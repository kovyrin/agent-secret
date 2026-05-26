import Foundation

/// Value-only input for the Google Cloud OAuth bootstrap login prompt.
public struct GCPOAuthLoginPrompt: Equatable, Sendable {
    public let authorizationURL: URL
    public let googleAccount: String
    public let expectedEmail: String?
    public let scopes: [String]

    public var accountLabel: String {
        if let expectedEmail, !expectedEmail.isEmpty {
            return expectedEmail
        }
        if !googleAccount.isEmpty {
            return googleAccount
        }
        return "the selected Google account"
    }

    /// Creates sanitized prompt metadata without storing token or authorization-code state.
    public init(
        authorizationURL: URL,
        googleAccount: String,
        expectedEmail: String? = nil,
        scopes: [String] = []
    ) {
        self.authorizationURL = authorizationURL
        self.googleAccount = googleAccount.trimmingCharacters(in: .whitespacesAndNewlines)
        self.expectedEmail = expectedEmail?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.scopes = scopes.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }
}
