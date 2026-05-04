import Foundation

enum ApprovalProtocolFixture {
    static func data(_ name: String) throws -> Data {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
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
