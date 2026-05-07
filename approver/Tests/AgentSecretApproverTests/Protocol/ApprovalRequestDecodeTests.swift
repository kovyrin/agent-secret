@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalRequestDecodeTests: XCTestCase {
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
}
