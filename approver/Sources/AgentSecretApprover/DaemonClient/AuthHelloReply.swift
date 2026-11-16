import Foundation

struct AuthHelloReply: Decodable {
    struct Payload: Decodable {
        let port: String?
        let code: String?
    }

    let type: String
    let version: Int
    let payload: Payload?
}
