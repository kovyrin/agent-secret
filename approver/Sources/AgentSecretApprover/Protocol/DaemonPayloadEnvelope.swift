import Foundation

struct DaemonPayloadEnvelope<Payload: Codable>: Codable, DaemonEnvelopeMetadata {
    private enum CodingKeys: String, CodingKey {
        case nonce
        case payload
        case requestID = "request_id"
        case type
        case version
    }

    let nonce: String?
    let payload: Payload
    let requestID: String?
    let type: DaemonMessageType
    let version: Int
}
