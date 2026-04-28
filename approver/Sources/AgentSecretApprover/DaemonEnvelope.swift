import Foundation

internal struct DaemonEnvelope<Payload: Codable>: Codable {
    private enum CodingKeys: String, CodingKey {
        case nonce = "nonce"
        case payload = "payload"
        case requestID = "request_id"
        case type = "type"
        case version = "version"
    }

    internal let nonce: String?
    internal let payload: Payload?
    internal let requestID: String?
    internal let type: String
    internal let version: Int
}
