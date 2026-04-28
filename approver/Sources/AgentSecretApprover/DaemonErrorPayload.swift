import Foundation

internal struct DaemonErrorPayload: Codable {
    internal let code: String
    internal let message: String
}
