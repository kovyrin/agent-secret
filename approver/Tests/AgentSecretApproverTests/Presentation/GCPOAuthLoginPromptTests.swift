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
                "Manage your Identity and Access Management (IAM) Policies"
            )
        )
        XCTAssertTrue(GCPOAuthLoginPromptCopy.meaningText.contains("does not create service accounts"))
        XCTAssertTrue(GCPOAuthLoginPromptCopy.meaningText.contains("does not"))
        XCTAssertTrue(GCPOAuthLoginPromptCopy.adminRiskText.contains("Owner"))
        XCTAssertTrue(GCPOAuthLoginPromptCopy.adminRiskText.contains("Service Account Token Creator"))
        XCTAssertTrue(GCPOAuthLoginPromptCopy.retryText.contains("wrong Chrome profile"))
    }

    func testConsentItemsUseGoogleLabelsForDefaultScopes() {
        let titles = GCPOAuthLoginPromptCopy.consentItems(for: []).map(\.title)

        XCTAssertEqual(
            titles,
            [
                "Manage your Identity and Access Management (IAM) Policies",
                "See your primary Google Account email address",
                "Associate you with your personal info on Google"
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
