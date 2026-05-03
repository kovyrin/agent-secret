@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(Darwin)
    import Darwin

    final class DaemonPeerValidationTeamIDTests: XCTestCase {
        private final class FakeSignatureChecker: DaemonCodeSignatureChecking {
            var staticTeamIDResult: Result<String, Error> = .success("TEAMID")
            var processTeamIDResult: Result<String, Error> = .success("TEAMID")
            private(set) var staticPaths: [String] = []
            private(set) var processPIDs: [pid_t] = []

            func staticCodeTeamID(for path: String) throws -> String {
                staticPaths.append(path)
                return try staticTeamIDResult.get()
            }

            func processTeamID(for pid: pid_t) throws -> String {
                processPIDs.append(pid)
                return try processTeamIDResult.get()
            }

            deinit {
                /* Required by SwiftLint. */
            }
        }

        private static func makeAppBundleExecutable(testCase: XCTestCase) throws -> String {
            let appDirectory = URL(fileURLWithPath: "/tmp")
                .appendingPathComponent("agent-secret-swift-app-\(UUID().uuidString)")
                .appendingPathExtension("app")
            let executableDirectory = appDirectory
                .appendingPathComponent("Contents")
                .appendingPathComponent("MacOS")
            try FileManager.default.createDirectory(at: executableDirectory, withIntermediateDirectories: true)
            let executable = executableDirectory.appendingPathComponent("Agent Secret")
            try "#!/bin/sh\nexit 0\n".write(to: executable, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: executable.path)
            testCase.addTeardownBlock {
                try? FileManager.default.removeItem(at: appDirectory)
            }
            return executable.path
        }

        func testRejectsBundledDaemonWhenExpectedTeamIDIsMissing() throws {
            let executable = try Self.makeAppBundleExecutable(testCase: self)
            let checker = FakeSignatureChecker()
            let validator = TrustedDaemonPeerValidator(
                expectedExecutablePaths: [executable],
                expectedTeamID: "",
                signatureChecker: checker
            )
            let info = DaemonPeerInfo(
                uid: getuid(),
                gid: getgid(),
                pid: getpid(),
                executablePath: executable
            )

            XCTAssertThrowsError(try validator.validateDaemonPeer(info)) { error in
                XCTAssertEqual(
                    error as? SocketDaemonClientError,
                    .untrustedDaemon("expected Developer ID Team ID is required for daemon signature validation")
                )
            }
            XCTAssertTrue(checker.staticPaths.isEmpty)
            XCTAssertTrue(checker.processPIDs.isEmpty)
        }

        func testAllowsDevelopmentTeamIDSentinelForBundledDaemon() throws {
            let executable = try Self.makeAppBundleExecutable(testCase: self)
            let checker = FakeSignatureChecker()
            checker.staticTeamIDResult = .failure(SocketDaemonClientError.untrustedDaemon("static check called"))
            checker.processTeamIDResult = .failure(SocketDaemonClientError.untrustedDaemon("process check called"))
            let validator = TrustedDaemonPeerValidator(
                expectedExecutablePaths: [executable],
                expectedTeamID: "-",
                signatureChecker: checker
            )
            let info = DaemonPeerInfo(
                uid: getuid(),
                gid: getgid(),
                pid: getpid(),
                executablePath: executable
            )

            XCTAssertNoThrow(try validator.validateDaemonPeer(info))
            XCTAssertTrue(checker.staticPaths.isEmpty)
            XCTAssertTrue(checker.processPIDs.isEmpty)
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }
#endif
