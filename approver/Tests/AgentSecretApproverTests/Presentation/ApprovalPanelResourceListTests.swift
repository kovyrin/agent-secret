@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(SwiftUI)
    final class ApprovalPanelResourceListTests: XCTestCase {
        private typealias Metric = ApprovalPanelStyle.Metric

        func testAliasColumnWidthExpandsForLongAliases() {
            let aliases = ["PLANETSCALE_SERVICE_TOKEN_ID", "PLANETSCALE_SERVICE_TOKEN"]

            let width = ApprovalPanelResourceListLayout.aliasColumnWidth(for: aliases)

            XCTAssertGreaterThan(width, Metric.resourceListAliasMinimumWidth)
            XCTAssertLessThanOrEqual(width, Metric.resourceListAliasMaximumWidth)
        }

        func testAliasColumnWidthKeepsMinimumForShortAliases() {
            let width = ApprovalPanelResourceListLayout.aliasColumnWidth(for: ["TOKEN"])

            XCTAssertEqual(width, Metric.resourceListAliasMinimumWidth)
        }

        func testAliasColumnWidthCapsVeryLongAliases() {
            let width = ApprovalPanelResourceListLayout.aliasColumnWidth(for: [
                "EXCEPTIONALLY_LONG_SERVICE_ACCOUNT_ACCESS_TOKEN"
            ])

            XCTAssertEqual(width, Metric.resourceListAliasMaximumWidth)
        }
    }
#endif
