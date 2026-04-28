import Foundation

internal struct DaemonHeader: Decodable {
    internal let type: String
    internal let version: Int
}
