import Foundation

struct AuthHelloReply: Decodable {
    struct Payload: Decodable {
        let port: String?
        let code: DaemonErrorCode?
    }

    let type: DaemonMessageType
    let version: Int
    let payload: Payload?
}
