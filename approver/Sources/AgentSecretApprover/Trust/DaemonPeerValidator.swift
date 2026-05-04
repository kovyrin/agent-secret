import Foundation

#if canImport(Darwin)
    protocol DaemonPeerValidator {
        func validateDaemonPeer(_ info: DaemonPeerInfo) throws
    }
#endif
