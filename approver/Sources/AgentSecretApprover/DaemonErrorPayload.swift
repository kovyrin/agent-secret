import Foundation

struct DaemonErrorPayload: Codable {
    let code: DaemonErrorCode
    let message: String
}
