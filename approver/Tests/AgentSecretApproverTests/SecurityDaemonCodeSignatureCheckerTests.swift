@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(Darwin)
    final class SecurityDaemonCodeSignatureCheckerTests: XCTestCase {
        private struct ProcessRunnerCall: Equatable {
            let executableURL: URL
            let arguments: [String]
            let timeout: TimeInterval
        }

        private final class FakeCodeSignatureProcessRunner: CodeSignatureProcessRunning {
            private var results: [Result<CodeSignatureProcessResult, Error>]
            private(set) var calls: [ProcessRunnerCall] = []

            init(results: [Result<CodeSignatureProcessResult, Error>]) {
                self.results = results
            }

            func run(
                executableURL: URL,
                arguments: [String],
                timeout: TimeInterval
            ) throws -> CodeSignatureProcessResult {
                calls.append(ProcessRunnerCall(executableURL: executableURL, arguments: arguments, timeout: timeout))
                return try results.removeFirst().get()
            }

            deinit {
                /* Required by SwiftLint. */
            }
        }

        private static let largeOutputByteCount = 200_000
        private static let minimumLargeOutputBytes = 100_000

        func testProcessTeamIDVerifiesAndParsesCodesignOutput() throws {
            let runner = FakeCodeSignatureProcessRunner(results: [
                .success(CodeSignatureProcessResult(output: "", terminationStatus: 0)),
                .success(
                    CodeSignatureProcessResult(
                        output: "Authority=Example\nTeamIdentifier=TEAMID\n",
                        terminationStatus: 0
                    )
                )
            ])
            let checker = SecurityDaemonCodeSignatureChecker(codesignRunner: runner, codesignTimeout: 0.25)
            let pid: pid_t = 123

            XCTAssertEqual(try checker.processTeamID(for: pid), "TEAMID")
            XCTAssertEqual(runner.calls, [
                .init(
                    executableURL: URL(fileURLWithPath: "/usr/bin/codesign"),
                    arguments: ["--verify", "--strict", "--deep", "+123"],
                    timeout: 0.25
                ),
                .init(
                    executableURL: URL(fileURLWithPath: "/usr/bin/codesign"),
                    arguments: ["-dv", "--verbose=4", "+123"],
                    timeout: 0.25
                )
            ])
        }

        func testProcessTeamIDRejectsNonZeroCodesignStatus() {
            let runner = FakeCodeSignatureProcessRunner(results: [
                .success(CodeSignatureProcessResult(output: "bad signature", terminationStatus: 1))
            ])
            let checker = SecurityDaemonCodeSignatureChecker(codesignRunner: runner, codesignTimeout: 0.25)

            XCTAssertThrowsError(try checker.processTeamID(for: 123)) { error in
                XCTAssertEqual(
                    error as? SocketDaemonClientError,
                    .untrustedDaemon("daemon process code signature validation failed with status 1")
                )
            }
        }

        func testFoundationRunnerReturnsOutputAndStatus() throws {
            let runner = FoundationCodeSignatureProcessRunner()

            let result = try runner.run(
                executableURL: URL(fileURLWithPath: "/bin/sh"),
                arguments: ["-c", "printf hello"],
                timeout: 1
            )

            XCTAssertEqual(result.output, "hello")
            XCTAssertEqual(result.terminationStatus, 0)
        }

        func testFoundationRunnerReturnsNonZeroStatusWithoutThrowing() throws {
            let runner = FoundationCodeSignatureProcessRunner()

            let result = try runner.run(
                executableURL: URL(fileURLWithPath: "/bin/sh"),
                arguments: ["-c", "printf nope; exit 7"],
                timeout: 1
            )

            XCTAssertEqual(result.output, "nope")
            XCTAssertEqual(result.terminationStatus, 7)
        }

        func testFoundationRunnerDrainsLargeOutput() throws {
            let runner = FoundationCodeSignatureProcessRunner()

            let result = try runner.run(
                executableURL: URL(fileURLWithPath: "/bin/sh"),
                arguments: ["-c", "yes agent-secret | head -c \(Self.largeOutputByteCount)"],
                timeout: 1
            )

            XCTAssertGreaterThan(result.output.count, Self.minimumLargeOutputBytes)
            XCTAssertEqual(result.terminationStatus, 0)
        }

        func testFoundationRunnerTimesOutHungProcess() {
            let runner = FoundationCodeSignatureProcessRunner()
            let startedAt = Date()

            XCTAssertThrowsError(
                try runner.run(
                    executableURL: URL(fileURLWithPath: "/bin/sleep"),
                    arguments: ["5"],
                    timeout: 0.05
                )
            ) { error in
                XCTAssertEqual(
                    error as? SocketDaemonClientError,
                    .untrustedDaemon("daemon process code signature validation timed out")
                )
            }
            XCTAssertLessThan(Date().timeIntervalSince(startedAt), 2)
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }
#endif
