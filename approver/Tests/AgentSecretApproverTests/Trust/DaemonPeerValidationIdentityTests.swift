@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(Darwin)
    import Darwin

    final class DaemonPeerValidationIdentityTests: XCTestCase {
        private static func makeExecutable(testCase: XCTestCase) throws -> String {
            let directory = URL(fileURLWithPath: "/tmp")
                .appendingPathComponent("agent-secret-swift-executable-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let executable = directory.appendingPathComponent("agent-secretd")
            try "#!/bin/sh\nexit 0\n".write(to: executable, atomically: false, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: executable.path)
            testCase.addTeardownBlock {
                try? FileManager.default.removeItem(at: directory)
            }
            return executable.path
        }

        func testTrustedDaemonValidatorRejectsExecutableMutatedAfterTrustSnapshot() throws {
            let executable = try Self.makeExecutable(testCase: self)
            let validator = TrustedDaemonPeerValidator(
                expectedExecutablePaths: [executable],
                expectedTeamID: "-"
            )
            try "#!/bin/sh\nexit 64\n# changed\n".write(
                to: URL(fileURLWithPath: executable),
                atomically: false,
                encoding: .utf8
            )
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: executable)
            let info = DaemonPeerInfo(
                uid: getuid(),
                gid: getgid(),
                pid: getpid(),
                executablePath: executable
            )

            XCTAssertThrowsError(try validator.validateDaemonPeer(info)) { error in
                XCTAssertEqual(
                    error as? DaemonTrustError,
                    .untrustedDaemon("daemon executable changed since trust snapshot")
                )
            }
        }
    }
#endif
