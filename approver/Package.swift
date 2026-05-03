// swift-tools-version: 6.1

import PackageDescription

// swiftlint:disable:next prefixed_toplevel_constant
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
            name: "agent-secret-app",
            targets: ["AgentSecretApproverApp"]
        ),
        .executable(
            name: "agent-secret-app-smoke",
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
