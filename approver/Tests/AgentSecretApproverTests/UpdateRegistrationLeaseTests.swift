@testable import AgentSecretApprover
import Darwin
import XCTest

final class UpdateRegistrationLeaseTests: XCTestCase {
    func testRegistrationRunsWithoutAnInstaller() throws {
        let app = try temporaryApplication()
        defer { try? FileManager.default.removeItem(at: app.deletingLastPathComponent()) }
        var registered = false

        try withUpdateRegistrationLease(at: app) { registered = true }

        XCTAssertTrue(registered)
    }

    func testRegistrationCannotStartUnderAnInstallerLease() throws {
        let app = try temporaryApplication()
        defer { try? FileManager.default.removeItem(at: app.deletingLastPathComponent()) }
        let descriptor = open(app.deletingLastPathComponent().path, O_RDONLY)
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        defer { close(descriptor) }
        XCTAssertEqual(flock(descriptor, LOCK_EX | LOCK_NB), 0)
        var registered = false

        XCTAssertThrowsError(try withUpdateRegistrationLease(at: app) { registered = true })

        XCTAssertFalse(registered)
    }

    func testPendingRecoveryPreventsRegistration() throws {
        let app = try temporaryApplication()
        defer { try? FileManager.default.removeItem(at: app.deletingLastPathComponent()) }
        let marker = app.deletingLastPathComponent().appendingPathComponent(".agent-secret-update")
        try Data().write(to: marker)
        var registered = false

        XCTAssertThrowsError(try withUpdateRegistrationLease(at: app) { registered = true })

        XCTAssertFalse(registered)
    }

    private func temporaryApplication() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("Agent Secret.app")
    }
}
