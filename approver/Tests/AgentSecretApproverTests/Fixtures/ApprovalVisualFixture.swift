@testable import AgentSecretApprover
import Foundation

enum ApprovalVisualFixture {
    enum Variant: Int, CaseIterable {
        case bitwarden = 3
        case environment = 7
        case highScope = 6
        case metadata = 4
        case multipleAccounts = 2
        case overrides = 8
        case session = 5
        case single = 1
    }

    private static let requestSeconds: TimeInterval = 120
    private static let accessSeconds = 300
    private static let sessionReads = 2
    private static let maximumResources = 7
    private static let boundPID: Int = 501
    private static let creatorPID: Int = 502

    static func request(_ variant: Variant) throws -> ApprovalRequest {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        var request = try decoder.decode(ApprovalRequest.self, from: ApprovalProtocolFixture.data("approval_request"))
        request.expiresAt = Date().addingTimeInterval(requestSeconds)
        request.requestTTLSeconds = requestSeconds
        request.overrideEnv = false
        request.overriddenAliases = []
        request.reason = "Review the sample service configuration and deployment plan. No service changes are intended."
        configure(&request, variant: variant)
        return request
    }

    private static func configure(_ request: inout ApprovalRequest, variant: Variant) {
        switch variant {
        case .multipleAccounts:
            request.resources += [
                RequestedResource(alias: "PERSONAL_TOKEN", ref: "op://Shared/Deploy/token", account: "Personal"),
                RequestedResource(alias: "METRICS_TOKEN", ref: "op://Shared/Metrics/token", account: "Work")
            ]

        case .bitwarden:
            request.resources = [
                RequestedResource(
                    alias: "BUILD_TOKEN",
                    ref: "bws://00000000-0000-0000-0000-000000000001",
                    account: "",
                    source: "build-service",
                    bitwardenTokenAlias: "BUILD_ACCESS_TOKEN"
                )
            ]

        case .metadata:
            configureMetadata(&request)

        case .session:
            request.operation = .sessionCreate
            request.allowsReusable = false
            request.reusableUses = 1
            request.reason = "Run two commands for the example service using a bounded session."
            request.accessDurationSeconds = accessSeconds
            request.requestTTLSeconds = TimeInterval(accessSeconds)
            request.expiresAt = Date().addingTimeInterval(TimeInterval(accessSeconds))
            request.sessionMaxReads = sessionReads
            request.command = ["agent-secret", "session", "create"]
            request.resolvedExecutable = "/usr/local/bin/agent-secret"
            request.sessionBinding = sessionBinding()

        case .highScope:
            request.resources = (1 ... maximumResources).map { index in
                RequestedResource(
                    alias: "SERVICE_TOKEN_\(index)", ref: "op://Services/Service \(index)/token", account: "Work"
                )
            }

        case .environment:
            request.resolvedExecutable = "/usr/bin/env"
            request.command = ["/usr/bin/env"]

        case .overrides:
            request.allowMutableExecutable = true
            request.overrideEnv = true
            request.overriddenAliases = ["EXAMPLE_TOKEN"]

        case .single:
            break
        }
    }

    private static func configureMetadata(_ request: inout ApprovalRequest) {
        request.operation = .itemDescribe
        request.allowsReusable = false
        request.reusableUses = 1
        request.reason = "Inspect names and field metadata for the example deployment item."
        request.command = ["agent-secret", "item", "describe", "op://Shared/Deploy"]
        request.resources = [RequestedResource(alias: "Deploy", ref: "op://Shared/Deploy", account: "Work")]
        request.resolvedExecutable = "/usr/local/bin/agent-secret"
    }

    private static func sessionBinding() -> SessionBindingInfo {
        SessionBindingInfo(
            mode: "ancestor_name",
            boundProcess: SessionBindingProcess(
                pid: boundPID, name: "sample-agent", path: "/usr/local/bin/sample-agent"
            ),
            creatorProcess: SessionBindingProcess(
                pid: creatorPID, name: "agent-secret", path: "/usr/local/bin/agent-secret"
            )
        )
    }
}
