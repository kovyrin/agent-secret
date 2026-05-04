import Foundation

#if canImport(Darwin)
    import Darwin

    struct DaemonPeerInfo: Equatable {
        let uid: uid_t
        let gid: gid_t
        let pid: pid_t
        let executablePath: String
    }
#endif
