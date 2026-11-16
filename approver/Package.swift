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
        ),
        .executable(
            name: "agent-secret-updater",
            targets: ["AgentSecretUpdaterApp"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.1")
    ],
    targets: [
        .target(
            name: "AgentSecretMachAuth",
            publicHeadersPath: "include"
        ),
        .target(name: "AgentSecretApprover", dependencies: ["AgentSecretMachAuth"]),
        .executableTarget(
            name: "AgentSecretApproverApp",
            dependencies: ["AgentSecretApprover"]
        ),
        .executableTarget(
            name: "AgentSecretApproverSmoke",
            dependencies: ["AgentSecretApprover"]
        ),
        .executableTarget(
            name: "AgentSecretUpdaterApp",
            dependencies: ["AgentSecretApprover", .product(name: "Sparkle", package: "Sparkle")],
            linkerSettings: [
                .unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@loader_path/../../../../../Frameworks"])
            ]
        ),
        .testTarget(
            name: "AgentSecretApproverTests",
            dependencies: ["AgentSecretApprover", "AgentSecretApproverApp"]
        ),
        .testTarget(
            name: "AgentSecretUpdaterTests",
            dependencies: ["AgentSecretUpdaterApp"]
        )
    ]
)
