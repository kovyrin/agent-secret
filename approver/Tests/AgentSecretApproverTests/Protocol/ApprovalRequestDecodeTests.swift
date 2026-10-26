@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalRequestDecodeTests: XCTestCase {
    func testSharedCurrentAndLegacyFixtures() throws {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let current = try decoder.decode(ApprovalRequest.self, from: ApprovalProtocolFixture.data("approval_request"))
        let legacy = try decoder.decode(
            ApprovalRequest.self,
            from: ApprovalProtocolFixture.data("approval_request_legacy")
        )
        XCTAssertEqual(current.requestTTLSeconds, 120.5)
        XCTAssertNil(legacy.requestTTLSeconds)
        XCTAssertNil(legacy.sessionMaxReads)
        XCTAssertEqual(current.resources, legacy.resources)
    }

    func testOptionalLimitsPreserveLegacyAndNullFallbacks() throws {
        for value in [nil, NSNull()] as [Any?] {
            let request = try decodeLimits(ttl: value, reads: value)
            XCTAssertNil(request.requestTTLSeconds)
            XCTAssertNil(request.sessionMaxReads)
        }
    }

    func testOptionalLimitsAcceptValidatedBoundsAndFractionalTTL() throws {
        for ttl in [10.0, 120.5, 600.0] {
            for reads in [1, 2, 100] {
                let request = try decodeLimits(ttl: ttl, reads: reads)
                XCTAssertEqual(request.requestTTLSeconds, ttl)
                XCTAssertEqual(request.sessionMaxReads, reads)
            }
        }
    }

    func testOptionalLimitsRejectInvalidNumbersAndTypes() {
        for ttl in [0, 9.99, 600.01, "120", true] as [Any] {
            XCTAssertThrowsError(try decodeLimits(ttl: ttl, reads: 2))
        }
        for reads in [0, 101, 1.5, "2", true] as [Any] {
            XCTAssertThrowsError(try decodeLimits(ttl: 120, reads: reads))
        }
    }

    private func decodeLimits(ttl: Any?, reads: Any?) throws -> ApprovalRequest {
        let fixture = try ApprovalProtocolFixture.data("approval_request")
        var fields = try XCTUnwrap(JSONSerialization.jsonObject(with: fixture) as? [String: Any])
        fields["request_ttl_seconds"] = ttl
        fields["session_max_reads"] = reads
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(ApprovalRequest.self, from: JSONSerialization.data(withJSONObject: fields))
    }

    func testApprovalRequestDecodeRequiresCurrentProtocolFields() throws {
        let fixture: Data = try ApprovalProtocolFixture.data("approval_request")
        let object: Any = try JSONSerialization.jsonObject(with: fixture)
        guard let fixtureFields = object as? [String: Any] else {
            XCTFail("approval request fixture must be a JSON object")
            return
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        for field in [
            "allow_mutable_executable",
            "allows_reusable",
            "operation",
            "override_env",
            "overridden_aliases",
            "resolved_executable",
            "reusable_uses"
        ] {
            var payloadFields = fixtureFields
            payloadFields.removeValue(forKey: field)
            let payload: Data = try JSONSerialization.data(withJSONObject: payloadFields)

            XCTAssertThrowsError(
                try decoder.decode(ApprovalRequest.self, from: payload),
                "missing \(field) should fail decoding"
            )
        }
    }

    func testApprovalRequestDecodeRejectsNullRequiredProtocolFields() throws {
        let fixture: Data = try ApprovalProtocolFixture.data("approval_request")
        let object: Any = try JSONSerialization.jsonObject(with: fixture)
        guard let fixtureFields = object as? [String: Any] else {
            XCTFail("approval request fixture must be a JSON object")
            return
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        var payloadFields = fixtureFields
        payloadFields["resolved_executable"] = NSNull()
        let payload: Data = try JSONSerialization.data(withJSONObject: payloadFields)

        XCTAssertThrowsError(
            try decoder.decode(ApprovalRequest.self, from: payload),
            "null resolved_executable should fail decoding"
        )
    }

    func testApprovalRequestDecodeRequiresResourceAccount() throws {
        let fixture: Data = try ApprovalProtocolFixture.data("approval_request")
        let object: Any = try JSONSerialization.jsonObject(with: fixture)
        guard
            var fixtureFields = object as? [String: Any],
            let fixtureResources = fixtureFields["resources"] as? [[String: Any]],
            var firstResource = fixtureResources.first
        else {
            XCTFail("approval request fixture must include a resource object")
            return
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        firstResource.removeValue(forKey: "account")
        fixtureFields["resources"] = [firstResource]
        var payload: Data = try JSONSerialization.data(withJSONObject: fixtureFields)
        XCTAssertThrowsError(
            try decoder.decode(ApprovalRequest.self, from: payload),
            "missing resource account should fail decoding"
        )

        firstResource["account"] = NSNull()
        fixtureFields["resources"] = [firstResource]
        payload = try JSONSerialization.data(withJSONObject: fixtureFields)
        XCTAssertThrowsError(
            try decoder.decode(ApprovalRequest.self, from: payload),
            "null resource account should fail decoding"
        )
    }

    func testApprovalRequestDecodesAccessDurationWhenPresent() throws {
        let fixture: Data = try ApprovalProtocolFixture.data("approval_request")
        let object: Any = try JSONSerialization.jsonObject(with: fixture)
        guard var fixtureFields = object as? [String: Any] else {
            XCTFail("approval request fixture must be a JSON object")
            return
        }
        fixtureFields["access_duration_seconds"] = 300
        let payload: Data = try JSONSerialization.data(withJSONObject: fixtureFields)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let request = try decoder.decode(ApprovalRequest.self, from: payload)

        XCTAssertEqual(request.accessDurationSeconds, 300)
    }
}
