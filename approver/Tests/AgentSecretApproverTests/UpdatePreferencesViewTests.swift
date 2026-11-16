@testable import AgentSecretApproverApp
import XCTest

@MainActor
final class UpdatePreferencesViewTests: XCTestCase {
    func testAccessoryFrameFitsTheUpdateControls() {
        let accessory = UpdatePreferencesView()

        XCTAssertGreaterThan(accessory.frame.width, 0)
        XCTAssertGreaterThan(accessory.frame.height, 0)
        XCTAssertEqual(accessory.frame.size, accessory.fittingSize)
    }
}
