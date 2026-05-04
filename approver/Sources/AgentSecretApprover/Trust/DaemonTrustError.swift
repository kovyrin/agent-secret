import Foundation

enum DaemonTrustError: Error, Equatable {
    case untrustedDaemon(String)

    var message: String {
        switch self {
        case let .untrustedDaemon(message):
            message
        }
    }
}
