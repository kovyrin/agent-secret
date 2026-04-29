import Foundation

struct DaemonEnvelope<Payload: Codable>: Codable {
    private enum CodingKeys: String, CodingKey {
        case nonce
        case payload
        case requestID = "request_id"
        case type
        case version
    }

    let nonce: String?
    let payload: Payload?
    let requestID: String?
    let type: String
    let version: Int
}
