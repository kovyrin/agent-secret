import Foundation
import XCTest

final class ApproverAppEntrypointTests: XCTestCase {
    private static let appEntrypointPath: String = "Sources/AgentSecretApproverApp/AgentSecretApproverMain.swift"
    private static let mockClientSymbol: String = "MockDaemonClient"
    private static let mockDecisionFlag: String = "--mock-decision"
    private static let mockPresenterSymbol: String = "StaticDecisionPresenter"
    private static let mockRequestFlag: String = "--mock-request"
    private static let packageDirectoryName: String = "approver"
    private static let smokeEntrypointPath: String = "Sources/AgentSecretApproverSmoke/main.swift"
    private static let healthCheckFlag: String = "--health-check"
    private static let mainActorIsolationEscapeHatch: String = "assumeIsolated"

    private static func packageRootURL() -> URL? {
        var url = URL(fileURLWithPath: #filePath)
        while url.lastPathComponent != packageDirectoryName {
            let parent = url.deletingLastPathComponent()
            if parent.path == url.path {
                return nil
            }
            url = parent
        }
        return url
    }

    private static func sourceText(at relativePath: String) throws -> String {
        let root: URL = try XCTUnwrap(packageRootURL())
        return try String(
            contentsOf: root.appendingPathComponent(relativePath),
            encoding: .utf8
        )
    }

    func testShippedApproverEntrypointDoesNotContainMockOnlySurface() throws {
        let source: String = try Self.sourceText(at: Self.appEntrypointPath)

        XCTAssertFalse(source.contains(Self.mockRequestFlag))
        XCTAssertFalse(source.contains(Self.mockDecisionFlag))
        XCTAssertFalse(source.contains(Self.mockClientSymbol))
        XCTAssertFalse(source.contains(Self.mockPresenterSymbol))
    }

    func testShippedApproverEntrypointProvidesNonSecretHealthCheck() throws {
        let source: String = try Self.sourceText(at: Self.appEntrypointPath)

        XCTAssertTrue(source.contains(Self.healthCheckFlag))
        XCTAssertTrue(source.contains("agent-secret-approver: ok"))
    }

    func testShippedApproverEntrypointDoesNotAssumeMainActorIsolation() throws {
        let source: String = try Self.sourceText(at: Self.appEntrypointPath)

        XCTAssertFalse(source.contains(Self.mainActorIsolationEscapeHatch))
        XCTAssertTrue(source.contains("@MainActor"))
        XCTAssertTrue(source.contains("static func main()"))
    }

    func testSmokeEntrypointOwnsMockOnlySurface() throws {
        let source: String = try Self.sourceText(at: Self.smokeEntrypointPath)

        XCTAssertTrue(source.contains(Self.mockRequestFlag))
        XCTAssertTrue(source.contains(Self.mockDecisionFlag))
        XCTAssertTrue(source.contains(Self.mockClientSymbol))
        XCTAssertTrue(source.contains(Self.mockPresenterSymbol))
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
