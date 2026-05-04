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

        for field in ["override_env", "overridden_aliases", "allow_mutable_executable", "reusable_uses"] {
            var payloadFields = fixtureFields
            payloadFields.removeValue(forKey: field)
            let payload: Data = try JSONSerialization.data(withJSONObject: payloadFields)

            XCTAssertThrowsError(
                try decoder.decode(ApprovalRequest.self, from: payload),
                "missing \(field) should fail decoding"
            )
        }
    }
}
