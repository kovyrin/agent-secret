@testable import AgentSecretApprover
import XCTest

#if canImport(SwiftUI)
    final class ApprovalPanelReasonCardTests: XCTestCase {
        func testCollapsedReasonIsTruncatedAndNotSelectable() {
            let mode = ApprovalPanelReasonTextMode(isExpanded: false)

            XCTAssertEqual(mode.lineLimit, 3)
            XCTAssertFalse(mode.allowsSelection)
        }

        func testExpandedReasonIsFullyVisibleAndSelectable() {
            let mode = ApprovalPanelReasonTextMode(isExpanded: true)

            XCTAssertNil(mode.lineLimit)
            XCTAssertTrue(mode.allowsSelection)
        }
    }
#endif
