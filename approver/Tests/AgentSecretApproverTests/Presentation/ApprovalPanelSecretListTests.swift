@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(SwiftUI)
    final class ApprovalPanelSecretListTests: XCTestCase {
        private typealias Metric = ApprovalPanelStyle.Metric

        func testAliasColumnWidthExpandsForLongAliases() {
            let aliases = ["PLANETSCALE_SERVICE_TOKEN_ID", "PLANETSCALE_SERVICE_TOKEN"]

            let width = ApprovalPanelSecretListLayout.aliasColumnWidth(for: aliases)

            XCTAssertGreaterThan(width, Metric.secretListAliasMinimumWidth)
            XCTAssertLessThanOrEqual(width, Metric.secretListAliasMaximumWidth)
        }

        func testAliasColumnWidthKeepsMinimumForShortAliases() {
            let width = ApprovalPanelSecretListLayout.aliasColumnWidth(for: ["TOKEN"])

            XCTAssertEqual(width, Metric.secretListAliasMinimumWidth)
        }

        func testAliasColumnWidthCapsVeryLongAliases() {
            let width = ApprovalPanelSecretListLayout.aliasColumnWidth(for: [
                "EXCEPTIONALLY_LONG_SERVICE_ACCOUNT_ACCESS_TOKEN"
            ])

            XCTAssertEqual(width, Metric.secretListAliasMaximumWidth)
        }
    }
#endif
