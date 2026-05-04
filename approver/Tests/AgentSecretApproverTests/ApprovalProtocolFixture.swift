import Foundation

enum ApprovalProtocolFixture {
    static func data(_ name: String) throws -> Data {
        let testDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let repositoryRoot = testDirectory
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let fixtureURL = repositoryRoot
            .appendingPathComponent("testdata")
            .appendingPathComponent("approval_protocol")
            .appendingPathComponent("\(name).json")
        return try Data(contentsOf: fixtureURL)
    }
}
