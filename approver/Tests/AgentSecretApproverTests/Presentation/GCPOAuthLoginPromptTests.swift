@testable import AgentSecretApprover
import Foundation
import XCTest

final class GCPOAuthLoginPromptTests: XCTestCase {
    func testPromptExplainsConsentAndBoundary() throws {
        let authorizationURL = try XCTUnwrap(URL(string: "https://accounts.example.invalid/oauth"))
        let prompt = GCPOAuthLoginPrompt(
            authorizationURL: authorizationURL,
            googleAccount: "personal",
            expectedEmail: "oleksiy@kovyrin.net",
            scopes: ["https://www.googleapis.com/auth/iam"]
        )

        XCTAssertEqual(prompt.accountLabel, "oleksiy@kovyrin.net")
        XCTAssertTrue(
            GCPOAuthLoginPromptCopy.consentItems(for: prompt.scopes).map(\.title).contains(
                "IAM policy scope"
            )
        )
        XCTAssertTrue(GCPOAuthLoginPromptCopy.meaningText.contains("does not create service accounts"))
        XCTAssertTrue(GCPOAuthLoginPromptCopy.meaningText.contains("does not"))
        XCTAssertTrue(GCPOAuthLoginPromptCopy.adminRiskText.contains("least-privileged Google account"))
        XCTAssertTrue(GCPOAuthLoginPromptCopy.adminRiskText.contains("Avoid Owner/IAM Admin accounts"))
        XCTAssertTrue(GCPOAuthLoginPromptCopy.adminRiskText.contains("Token Creator"))
        XCTAssertTrue(GCPOAuthLoginPromptCopy.retryText.contains("wrong Chrome profile"))
    }

    func testConsentItemsUseGoogleLabelsForDefaultScopes() {
        let titles = GCPOAuthLoginPromptCopy.consentItems(for: []).map(\.title)

        XCTAssertEqual(
            titles,
            [
                "IAM policy scope",
                "Email address",
                "Account identity"
            ]
        )
    }

    func testPromptFallsBackToAlias() throws {
        let authorizationURL = try XCTUnwrap(URL(string: "https://accounts.example.invalid/oauth"))
        let prompt = GCPOAuthLoginPrompt(
            authorizationURL: authorizationURL,
            googleAccount: "personal",
            expectedEmail: nil
        )

        XCTAssertEqual(prompt.accountLabel, "personal")
    }
}
