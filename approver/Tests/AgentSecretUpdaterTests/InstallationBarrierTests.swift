@testable import AgentSecretUpdaterApp
import Darwin
import Foundation
import XCTest

final class InstallationBarrierTests: XCTestCase {
    func testCommittedMarkerContainsRecoveryMetadataAndCanBeCancelledBeforeExtraction() throws {
        let parent = try createParent()
        defer { try? FileManager.default.removeItem(at: parent) }
        let barrier = InstallationBarrier(hostURL: parent.appendingPathComponent("Agent Secret.app"))
        let marker = parent.appendingPathComponent(".agent-secret-update")

        try barrier.begin(version: "1.0.35")
        let metadata = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: marker)) as? [String: String])
        XCTAssertEqual(metadata["version"], "1.0.35")
        XCTAssertNotNil(metadata["boot"].flatMap(UUID.init(uuidString:)))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: parent.path), [".agent-secret-update"])

        barrier.cancelBeforeExtraction()
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }

    func testAlreadyRunningWorkPreventsArmingAnUpdate() throws {
        let parent = try createParent()
        defer { try? FileManager.default.removeItem(at: parent) }
        let descriptor = open(parent.path, O_DIRECTORY | O_RDONLY | O_CLOEXEC)
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        defer { close(descriptor) }
        XCTAssertEqual(flock(descriptor, LOCK_SH | LOCK_NB), 0)
        let barrier = InstallationBarrier(hostURL: parent.appendingPathComponent("Agent Secret.app"))
        XCTAssertThrowsError(try barrier.begin(version: "1.0.35"))
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: parent.path).isEmpty)
    }

    private func createParent() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        return directory
    }
}
