import Foundation

struct DaemonHeader: Decodable {
    let type: DaemonMessageType
    let version: Int
}
