@testable import AgentSecretApproverApp
import XCTest

@MainActor
final class SettingsCoordinatorTests: XCTestCase {
    func testInstallPreservesConflictHandlingAndBootstrapFailureStaysInline() async {
        var cliCalls: [[String]] = []
        var hostCalls: [[String]] = []
        let coordinator = SettingsCoordinator(
            readState: {
                SettingsState(version: "fixture", cli: .repairNeeded, updatesConfigured: true, automaticChecks: true)
            },
            runCLI: { arguments, _ in
                cliCalls.append(arguments)
                return SettingsCommandRunner.Result(output: "Existing command conflict.", succeeded: false)
            },
            runHost: { arguments, timeout in
                hostCalls.append(arguments)
                XCTAssertEqual(timeout, 5)
                return SettingsCommandRunner.Result(output: "fixture registration failure", succeeded: false)
            }
        )

        await coordinator.bootstrap()

        XCTAssertEqual(hostCalls, [["--restore-background-updater"]])
        XCTAssertTrue(coordinator.state.activity.isEmpty)
        XCTAssertTrue(coordinator.state.updateNotice.contains("Reopen Settings to retry"))

        await coordinator.installCLI()

        XCTAssertEqual(cliCalls, [["install-cli"]])
        XCTAssertFalse(coordinator.state.busy)
    }

    func testOpeningDoesNotInvokeCommandsAndDiagnosticsKeepsMainWindow() async {
        var calls: [[String]] = []
        let coordinator = SettingsCoordinator(
            readState: {
                SettingsState(version: "fixture", cli: .installed, updatesConfigured: true, automaticChecks: false)
            },
            runCLI: { arguments, timeout in
                calls.append(arguments)
                XCTAssertEqual(timeout, 20)
                await Task.yield()
                return SettingsCommandRunner.Result(output: "fixture diagnostics", succeeded: true)
            },
            runHost: { _, _ in
                XCTFail("Opening Settings must not run a host command.")
                return SettingsCommandRunner.Result(output: "", succeeded: true)
            }
        )
        let window = coordinator.controller.window
        XCTAssertTrue(calls.isEmpty)

        await coordinator.runDiagnostics()

        XCTAssertEqual(calls, [["doctor"]])
        XCTAssertFalse(coordinator.state.busy)
        XCTAssertTrue(coordinator.state.activity.isEmpty)
        XCTAssertIdentical(coordinator.controller.window, window)
        XCTAssertEqual(coordinator.state.cli, .installed)
    }
}
