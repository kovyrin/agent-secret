@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalControllerTests: XCTestCase {
    private final class RecordingLogger: ApprovalLogger {
        private(set) var events: [String] = []

        func record(_ event: String, requestID: String?) {
            events.append("\(event):\(requestID ?? "none")")
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }

    private static let canarySecretValue: String = "synthetic-secret-value"
    private static let expectedReusableUses: Int = 3
    private static let sampleExpiration: TimeInterval = 1_800_000_000
    private static let viewModelNow: TimeInterval = 1_799_999_880

    private static var sampleRequest: ApprovalRequest {
        ApprovalRequest(
            requestID: "req_123",
            nonce: "nonce_456",
            reason: "Run Terraform plan for staging",
            command: ["/opt/homebrew/bin/terraform", "plan"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: sampleExpiration),
            secrets: [
                RequestedSecret(
                    alias: "EXAMPLE_TOKEN",
                    ref: "op://Example Vault/Example Item/token",
                    account: "Work"
                )
            ],
            resolvedExecutable: "/opt/homebrew/bin/terraform"
        )
    }

    private static var multiSecretRequest: ApprovalRequest {
        ApprovalRequest(
            requestID: "req_multi",
            nonce: "nonce_multi",
            reason: "Run integration checks",
            command: ["/usr/bin/env"],
            cwd: "/tmp/project",
            expiresAt: Date(timeIntervalSince1970: sampleExpiration),
            secrets: multiSecrets,
            resolvedExecutable: "/usr/bin/env"
        )
    }

    private static var multiSecrets: [RequestedSecret] {
        [
            RequestedSecret(alias: "LOGIN", ref: "op://Private/Github/username"),
            RequestedSecret(alias: "GITHUB_TOKEN", ref: "op://Private/Github/token"),
            RequestedSecret(alias: "GITHUB_EMAIL", ref: "op://Private/Github/email"),
            RequestedSecret(alias: "DB_HOST", ref: "op://Database/App/host"),
            RequestedSecret(alias: "DB_USER", ref: "op://Database/App/user"),
            RequestedSecret(alias: "DB_PASSWORD", ref: "op://Database/App/password"),
            RequestedSecret(alias: "DB_NAME", ref: "op://Database/App/name"),
            RequestedSecret(alias: "OPENAI_API_KEY", ref: "op://OpenAI/Platform/api_key"),
            RequestedSecret(alias: "OPENAI_ORG_ID", ref: "op://OpenAI/Platform/org_id"),
            RequestedSecret(alias: "OPENAI_PROJECT_ID", ref: "op://OpenAI/Platform/project_id")
        ]
    }

    private static var longScopeRequest: ApprovalRequest {
        ApprovalRequest(
            requestID: "req_long_scope",
            nonce: "nonce_long_scope",
            reason: "Run deployment with account-qualified references",
            command: [
                "/tmp/project/bin/deploy-with-secrets",
                "--environment",
                "production"
            ],
            cwd: "/tmp/project/services/release/with/a/very/long/path/component/that/must/stay-visible",
            expiresAt: Date(timeIntervalSince1970: sampleExpiration),
            secrets: [
                RequestedSecret(
                    alias: "SERVICE_TOKEN",
                    ref: "op://Very Long Production Vault/Service Token With Shared Prefix/token-ending-a",
                    account: "production-east-account-with-long-suffix-a"
                ),
                RequestedSecret(
                    alias: "SERVICE_TOKEN_BACKUP",
                    ref: "op://Very Long Production Vault/Service Token With Shared Prefix/token-ending-b",
                    account: "production-east-account-with-long-suffix-b"
                ),
                RequestedSecret(
                    alias: "DEPLOY_KEY",
                    ref: "op://Very Long Production Vault/Deploy Key/private-key",
                    account: "production-security-account"
                )
            ],
            resolvedExecutable: "/tmp/project/bin/deploy-with-secrets"
        )
    }

    private static func fixtureData(_ name: String) throws -> Data {
        let url: URL = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "json"))
        return try Data(contentsOf: url)
    }

    @MainActor
    func testReusableDecisionCarriesThreeUseLimit() async throws {
        let request: ApprovalRequest = Self.sampleRequest
        let client = MockDaemonClient(request: request)
        let controller = ApprovalController(
            client: client,
            presenter: StaticDecisionPresenter(decision: .approveReusable),
            logger: RecordingLogger()
        )

        let decision: ApprovalDecision = try await controller.run()

        XCTAssertEqual(decision.decision, .approveReusable)
        XCTAssertEqual(decision.reusableUses, Self.expectedReusableUses)
    }

    @MainActor
    func testPresenterContractIsMainActorAccessible() {
        let presenter: ApprovalPresenter = StaticDecisionPresenter(decision: .deny)

        XCTAssertEqual(presenter.decide(for: Self.sampleRequest), .deny)
    }

    func testSharedApprovalFixturesDecode() throws {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let request: ApprovalRequest = try decoder.decode(
            ApprovalRequest.self,
            from: Self.fixtureData("approval_request")
        )
        XCTAssertEqual(request.requestID, "req_123")
        XCTAssertEqual(request.nonce, "nonce_456")
        XCTAssertEqual(request.resolvedExecutable, "/opt/homebrew/bin/terraform")
        XCTAssertTrue(request.overrideEnv)
        XCTAssertEqual(request.overriddenAliases, ["EXAMPLE_TOKEN"])
        XCTAssertEqual(request.reusableUses, Self.expectedReusableUses)
        XCTAssertEqual(request.secrets.first?.ref, "op://Example Vault/Example Item/token")
        XCTAssertEqual(request.secrets.first?.account, "Work")

        let decision: ApprovalDecision = try decoder.decode(
            ApprovalDecision.self,
            from: Self.fixtureData("approval_decision")
        )
        XCTAssertEqual(decision.requestID, "req_123")
        XCTAssertEqual(decision.nonce, "nonce_456")
        XCTAssertEqual(decision.decision, .approveReusable)
        XCTAssertEqual(decision.reusableUses, Self.expectedReusableUses)
    }

    @MainActor
    func testSubmitsApproveOnceDecisionWithoutSecretValues() async throws {
        let request: ApprovalRequest = Self.sampleRequest
        let client = MockDaemonClient(request: request)
        let logger = RecordingLogger()
        let controller = ApprovalController(
            client: client,
            presenter: StaticDecisionPresenter(decision: .approveOnce),
            logger: logger
        )

        let decision: ApprovalDecision = try await controller.run()

        XCTAssertEqual(
            decision,
            ApprovalDecision(
                requestID: request.requestID,
                nonce: request.nonce,
                decision: .approveOnce
            )
        )
        XCTAssertEqual(client.submittedDecision, decision)

        let encoded: String = try String(data: JSONEncoder().encode(decision), encoding: .utf8) ?? ""
        XCTAssertFalse(encoded.contains("op://"))
        XCTAssertFalse(encoded.contains("EXAMPLE_TOKEN"))
        XCTAssertFalse(logger.events.contains { event -> Bool in event.contains("op://") })
    }

    func testViewModelContainsApprovalContextWithoutSecretValuesOrDebugIdentifiers() {
        var request: ApprovalRequest = Self.sampleRequest
        request.overrideEnv = true
        request.allowMutableExecutable = true
        request.overriddenAliases = ["EXAMPLE_TOKEN"]
        let viewModel = ApprovalRequestViewModel(
            request: request,
            now: Date(timeIntervalSince1970: Self.viewModelNow)
        )

        XCTAssertTrue(viewModel.renderedText.contains("Run Terraform plan"))
        XCTAssertTrue(viewModel.renderedText.contains("/tmp/project"))
        XCTAssertTrue(
            viewModel.renderedText.contains(
                "EXAMPLE_TOKEN [Account: Work] -> op://Example Vault/Example Item/token"
            )
        )
        XCTAssertTrue(viewModel.renderedText.contains("Resolved binary: /opt/homebrew/bin/terraform"))
        XCTAssertTrue(viewModel.renderedText.contains("Time remaining: 2 minutes"))
        XCTAssertTrue(viewModel.renderedText.contains("Will replace existing variables: EXAMPLE_TOKEN"))
        XCTAssertTrue(viewModel.renderedText.contains("Mutable executable opt-in"))
        XCTAssertTrue(viewModel.cautionMessages.contains { message in
            message.contains("Will replace existing variables: EXAMPLE_TOKEN")
        })
        XCTAssertTrue(viewModel.cautionMessages.contains { message in
            message.contains("Mutable executable opt-in")
        })
        XCTAssertEqual(viewModel.executable, "terraform")
        XCTAssertEqual(viewModel.promptQuestion, "Allow this command to use the following secret?")
        XCTAssertEqual(viewModel.accessSummary, "wants temporary access.")
        XCTAssertEqual(viewModel.compactTimeRemaining, "2 minutes")
        XCTAssertFalse(viewModel.isExpired)
        XCTAssertFalse(viewModel.commandNeedsInspector)
        XCTAssertFalse(viewModel.renderedText.contains(Self.canarySecretValue))
        XCTAssertFalse(viewModel.renderedText.contains(request.requestID))
        XCTAssertFalse(viewModel.renderedText.contains(request.nonce))
    }

    func testViewModelSummarizesManySecretsByVault() {
        let viewModel = ApprovalRequestViewModel(
            request: Self.multiSecretRequest,
            now: Date(timeIntervalSince1970: Self.viewModelNow)
        )

        XCTAssertEqual(viewModel.secretCount, Self.multiSecrets.count)
        XCTAssertEqual(viewModel.vaultCount, Self.expectedReusableUses)
        XCTAssertEqual(viewModel.promptQuestion, "Allow this command to use the following 10 secrets?")
        XCTAssertEqual(viewModel.accessSummary, "wants temporary access.")
        XCTAssertTrue(viewModel.highScopeWarning)
        XCTAssertTrue(viewModel.printsEnvironmentWarning)
        XCTAssertEqual(viewModel.vaultGroups.map(\.vaultName), ["Private", "Database", "OpenAI"])
        XCTAssertEqual(viewModel.vaultGroups.first?.countLabel, "3 secrets")
        XCTAssertEqual(viewModel.vaultGroups.first?.aliasSummary, "LOGIN, GITHUB_TOKEN, GITHUB_EMAIL")
        XCTAssertEqual(viewModel.requestedSecrets.first?.fieldName, "username")
        XCTAssertEqual(viewModel.requestedSecrets.first?.symbolName, "person")
        XCTAssertTrue(viewModel.footerMessage.contains("The secrets are injected"))
        XCTAssertFalse(viewModel.renderedText.contains(Self.canarySecretValue))
    }

    func testRequestInspectionTextContainsFullScopeValues() {
        var request: ApprovalRequest = Self.longScopeRequest
        request.overrideEnv = true
        request.overriddenAliases = ["SERVICE_TOKEN", "DEPLOY_KEY"]
        let viewModel = ApprovalRequestViewModel(
            request: request,
            now: Date(timeIntervalSince1970: Self.viewModelNow)
        )
        let inspection: String = viewModel.requestInspectionText

        XCTAssertTrue(inspection.contains(request.cwd))
        XCTAssertTrue(inspection.contains("/tmp/project/bin/deploy-with-secrets"))
        XCTAssertTrue(inspection.contains("Override existing environment: yes"))
        XCTAssertTrue(inspection.contains("- SERVICE_TOKEN"))
        XCTAssertTrue(inspection.contains("- DEPLOY_KEY"))
        XCTAssertTrue(
            inspection.contains("op://Very Long Production Vault/Service Token With Shared Prefix/token-ending-a")
        )
        XCTAssertTrue(
            inspection.contains("op://Very Long Production Vault/Service Token With Shared Prefix/token-ending-b")
        )
        XCTAssertTrue(inspection.contains("Account: production-east-account-with-long-suffix-a"))
        XCTAssertTrue(inspection.contains("Account: production-east-account-with-long-suffix-b"))
        XCTAssertTrue(inspection.contains("DEPLOY_KEY [Account: production-security-account]"))
        XCTAssertFalse(inspection.contains(Self.canarySecretValue))
        XCTAssertFalse(inspection.contains(request.requestID))
        XCTAssertFalse(inspection.contains(request.nonce))
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
