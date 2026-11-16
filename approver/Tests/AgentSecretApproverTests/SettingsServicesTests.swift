// swiftformat:options --decimalgrouping 3,3
@testable import AgentSecretApproverApp
import Foundation
import XCTest

final class SettingsServicesTests: XCTestCase {
    func testCLIStatusRecognizesHomebrewAndBrokenLinks() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let executable = root.appendingPathComponent("bundled-cli")
        let link = root.appendingPathComponent("agent-secret")
        try Data("fixture".utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        XCTAssertEqual(SettingsCLI.status(executable: executable, candidates: [link]), .missing)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: executable)
        XCTAssertEqual(SettingsCLI.status(executable: executable, candidates: [link]), .installed)
        try FileManager.default.removeItem(at: executable)
        XCTAssertEqual(SettingsCLI.status(executable: executable, candidates: [link]), .unavailable)
        try Data("fixture".utf8).write(to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        try FileManager.default.removeItem(at: link)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: root.appendingPathComponent("old-cli"))
        XCTAssertEqual(SettingsCLI.status(executable: executable, candidates: [link]), .repairNeeded)
    }

    func testCommandOutputIsBoundedWithoutPipeDeadlock() async {
        let result = await SettingsCommandRunner.run(
            executable: URL(fileURLWithPath: "/usr/bin/awk"),
            arguments: ["BEGIN { for (i=0; i<100000; i++) printf \"x\" }"],
            timeout: 2
        )
        XCTAssertTrue(result.succeeded)
        XCTAssertLessThan(result.output.utf8.count, 66_000)
        XCTAssertTrue(result.output.hasSuffix("[Output truncated.]"))
    }

    func testCommandTimesOutAndReturns() async {
        let start = Date()
        let result = await SettingsCommandRunner.run(
            executable: URL(fileURLWithPath: "/bin/sleep"), arguments: ["10"], timeout: 0.05
        )
        XCTAssertFalse(result.succeeded)
        XCTAssertTrue(result.output.contains("timed out"))
        XCTAssertLessThan(Date().timeIntervalSince(start), 2)
    }
}
