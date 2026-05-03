@testable import AgentSecretApprover
import Foundation
import XCTest

final class ApprovalRequestDecodeTests: XCTestCase {
    private static func fixtureData(_ name: String) throws -> Data {
        let url: URL = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "json"))
        return try Data(contentsOf: url)
    }

    func testApprovalRequestDecodeRequiresCurrentProtocolFields() throws {
        let fixture: Data = try Self.fixtureData("approval_request")
        let object: Any = try JSONSerialization.jsonObject(with: fixture)
        guard let fixtureFields = object as? [String: Any] else {
            XCTFail("approval request fixture must be a JSON object")
            return
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        for field in ["overrideEnv", "overriddenAliases", "allowMutableExecutable", "reusableUses"] {
            var payloadFields = fixtureFields
            payloadFields.removeValue(forKey: field)
            let payload: Data = try JSONSerialization.data(withJSONObject: payloadFields)

            XCTAssertThrowsError(
                try decoder.decode(ApprovalRequest.self, from: payload),
                "missing \(field) should fail decoding"
            )
        }
    }

    deinit {
        /* Required by SwiftLint. */
    }
}
