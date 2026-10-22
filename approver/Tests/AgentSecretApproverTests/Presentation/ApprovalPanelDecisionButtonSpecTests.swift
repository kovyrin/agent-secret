@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(SwiftUI)
    import SwiftUI

    final class ApprovalPanelDecisionButtonSpecTests: XCTestCase {
        private let now = Date(timeIntervalSince1970: 1_800_000_000)

        private func request() throws -> ApprovalRequest {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            var request = try decoder.decode(
                ApprovalRequest.self,
                from: ApprovalProtocolFixture.data("approval_request")
            )
            request.expiresAt = now.addingTimeInterval(120)
            return request
        }

        func testOnlyDenyHasShortcutAndVisiblePrimaryMatchesSelectedScope() throws {
            let request = try request()
            for scope in ApprovalScope.allCases {
                let specs = ApprovalPanelDecisionButtonSpec.makeAll(request: request, scope: scope, now: now)
                XCTAssertEqual(specs.count, 2)
                XCTAssertEqual(specs[0].decision, scope.decision(for: request))
                XCTAssertEqual(specs[0].title, scope == .once ? "Allow this run" : "Allow reuse")
                XCTAssertNil(specs[0].keyboardShortcut)
                XCTAssertTrue(specs[0].isEnabled)
                XCTAssertEqual(specs[1].decision, .deny)
                XCTAssertEqual(specs[1].keyboardShortcut, .cancelAction)
                XCTAssertTrue(specs.allSatisfy { $0.keyboardShortcut != .defaultAction })
            }
        }

        func testLookupAndSessionCannotSubmitReuseEvenWithStaleSelection() throws {
            var request = try request()
            for operation in [ApprovalOperation.itemDescribe, .sessionCreate] {
                request.operation = operation
                let specs = ApprovalPanelDecisionButtonSpec.makeAll(request: request, scope: .reusable, now: now)
                XCTAssertEqual(specs[0].decision, .approveOnce)
                XCTAssertEqual(specs[0].title, operation == .itemDescribe ? "Allow lookup" : "Start session")
            }
        }

        func testExactDeadlineDisablesAllowAndKeepsDenyAvailable() throws {
            let request = try request()
            let specs = ApprovalPanelDecisionButtonSpec.makeAll(
                request: request,
                scope: .reusable,
                now: request.expiresAt
            )
            XCTAssertFalse(specs[0].isEnabled)
            XCTAssertTrue(specs[1].isEnabled)
        }
    }
#endif
