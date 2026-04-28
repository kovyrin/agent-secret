// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "AgentSecretApprover",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "AgentSecretApprover",
            targets: ["AgentSecretApprover"]
        ),
        .executable(
            name: "agent-secret-approver",
            targets: ["AgentSecretApproverApp"]
        ),
        .executable(
            name: "agent-secret-approver-smoke",
            targets: ["AgentSecretApproverSmoke"]
        )
    ],
    targets: [
        .target(name: "AgentSecretApprover"),
        .executableTarget(
            name: "AgentSecretApproverApp",
            dependencies: ["AgentSecretApprover"]
        ),
        .executableTarget(
            name: "AgentSecretApproverSmoke",
            dependencies: ["AgentSecretApprover"]
        ),
        .testTarget(
            name: "AgentSecretApproverTests",
            dependencies: ["AgentSecretApprover"],
            resources: [.process("Fixtures")]
        )
    ]
)
