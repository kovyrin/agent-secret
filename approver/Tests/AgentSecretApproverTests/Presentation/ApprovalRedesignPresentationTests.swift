@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalRedesignPresentationTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func request() throws -> ApprovalRequest {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        var request = try decoder.decode(ApprovalRequest.self, from: ApprovalProtocolFixture.data("approval_request"))
        request.expiresAt = now.addingTimeInterval(30)
        request.requestTTLSeconds = 120
        return request
    }

    func testQueuedCountdownUsesOriginalLifetimeAndCeilingSeconds() throws {
        var request = try request()
        let countdown = ApprovalCountdown(request: request, now: now)
        XCTAssertEqual(countdown.clock, "0:30")
        XCTAssertEqual(countdown.fraction, 0.25)
        request.expiresAt = now.addingTimeInterval(0.1)
        XCTAssertEqual(ApprovalCountdown(request: request, now: now).clock, "0:01")
        request.requestTTLSeconds = nil
        XCTAssertNil(ApprovalCountdown(request: request, now: now).fraction)
    }

    func testCountdownThresholdsAndLateWake() throws {
        var request = try request()
        let cases: [(TimeInterval, ApprovalCountdown.Phase)] = [
            (120, .calm), (60.01, .calm), (60, .warning), (15.01, .warning),
            (15, .urgent), (0.01, .urgent), (0, .expired), (-90, .expired)
        ]
        for (remaining, expected) in cases {
            request.expiresAt = now.addingTimeInterval(remaining)
            let countdown = ApprovalCountdown(request: request, now: now)
            XCTAssertEqual(countdown.phase, expected)
            XCTAssertTrue(try (0 ... 1).contains(XCTUnwrap(countdown.fraction)))
        }
        request.expiresAt = now.addingTimeInterval(300)
        XCTAssertEqual(ApprovalCountdown(request: request, now: now).fraction, 1)
    }

    func testScopeCapabilitiesAndOperationMappings() throws {
        var request = try request()
        for count in [1, 2, 20] {
            request.reusableUses = count
            XCTAssertEqual(ApprovalScope.allowsReuse(request), count > 1)
            XCTAssertEqual(ApprovalScope.once.decision(for: request), .approveOnce)
            XCTAssertEqual(ApprovalScope.reusable.decision(for: request), count > 1 ? .approveReusable : .approveOnce)
        }
        request.resources = [RequestedResource(alias: "TOKEN", ref: "bws://example-id", account: "")]
        XCTAssertTrue(ApprovalScope.allowsReuse(request))
        for operation in [ApprovalOperation.itemDescribe, .sessionCreate] {
            request.operation = operation
            XCTAssertFalse(ApprovalScope.allowsReuse(request))
            XCTAssertEqual(ApprovalScope.reusable.decision(for: request), .approveOnce)
        }
    }

    func testSessionLimitsAreIndependentOfApprovalClockAndMissingLimitsAreHonest() throws {
        var request = try request()
        request.operation = .sessionCreate
        request.accessDurationSeconds = 300
        request.sessionMaxReads = 2
        let initial = ApprovalConsequences(request: request, scope: .once)
        XCTAssertEqual(initial.accessDuration, "5 minutes")
        XCTAssertEqual(initial.readLimit, "2 total reads")
        request.expiresAt = now
        XCTAssertEqual(ApprovalConsequences(request: request, scope: .once), initial)
        request.sessionMaxReads = nil
        XCTAssertEqual(ApprovalConsequences(request: request, scope: .once).readLimit, "Read limit unavailable")
    }

    func testIdentityDoesNotMergeFormattedLabelCollisionsOrTokenAliases() {
        let resources = [
            RequestedResource(alias: "A", ref: "op://C/Item/token", account: "A / B"),
            RequestedResource(alias: "B", ref: "op://B / C/Item/token", account: "A"),
            RequestedResource(
                alias: "C", ref: "bws://example-id", account: "", source: "ci", bitwardenTokenAlias: "ONE"
            ),
            RequestedResource(
                alias: "D", ref: "bws://example-id", account: "", source: "ci", bitwardenTokenAlias: "TWO"
            ),
            RequestedResource(alias: "E", ref: "op://D/Item/section/token", account: "A / B")
        ]
        let groups = ResourceAccountGroupViewModel.groups(resources)
        XCTAssertEqual(groups.count, 4)
        XCTAssertEqual(groups[0].resources.map(\.alias), ["A", "E"])
        XCTAssertEqual(groups[0].resources[1].ref, "op://D/Item/section/token")
        XCTAssertEqual(groups[2].identity.tokenAlias, "ONE")
        XCTAssertEqual(groups[3].identity.tokenAlias, "TWO")
    }

    func testWarningsComposeAtHighScopeThreshold() throws {
        var request = try request()
        request.resolvedExecutable = "/usr/bin/env"
        request.overrideEnv = true
        request.overriddenAliases = ["TOKEN"]
        request.allowMutableExecutable = true
        for count in [5, 6] {
            request.resources = (1 ... count).map { index in
                RequestedResource(alias: "TOKEN_\(index)", ref: "op://Example/Item/token", account: "Work")
            }
            let model = ApprovalRequestViewModel(request: request, now: now)
            XCTAssertEqual(model.highScopeWarning, count == 6)
            XCTAssertEqual(model.cautionMessages.count, 3)
            XCTAssertTrue(model.cautionMessages.contains { $0.contains("print environment") })
        }
    }
}
