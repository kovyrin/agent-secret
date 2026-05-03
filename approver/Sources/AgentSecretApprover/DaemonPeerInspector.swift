import Foundation

#if canImport(Darwin)
    import Darwin

    enum DaemonPeerInspector {
        // swiftlint:disable:next no_magic_numbers
        private static let pidPathCapacity: Int = .init(MAXPATHLEN) * 4

        static func inspect(socketFileDescriptor descriptor: Int32) throws -> DaemonPeerInfo {
            var uid: uid_t = 0
            var gid: gid_t = 0
            guard getpeereid(descriptor, &uid, &gid) == 0 else {
                throw SocketDaemonClientError.untrustedDaemon("getpeereid failed with errno \(errno)")
            }

            var cred = xucred()
            var credLength = socklen_t(MemoryLayout<xucred>.size)
            guard getsockopt(descriptor, 0, LOCAL_PEERCRED, &cred, &credLength) == 0 else {
                throw SocketDaemonClientError.untrustedDaemon("LOCAL_PEERCRED failed with errno \(errno)")
            }
            guard cred.cr_version == XUCRED_VERSION, cred.cr_ngroups > 0 else {
                throw SocketDaemonClientError.untrustedDaemon("LOCAL_PEERCRED returned incomplete metadata")
            }
            guard cred.cr_uid == uid, cred.cr_groups.0 == gid else {
                throw SocketDaemonClientError.untrustedDaemon("peer credential sources disagree")
            }

            var pid: pid_t = 0
            var pidLength = socklen_t(MemoryLayout<pid_t>.size)
            guard getsockopt(descriptor, 0, LOCAL_PEERPID, &pid, &pidLength) == 0 else {
                throw SocketDaemonClientError.untrustedDaemon("LOCAL_PEERPID failed with errno \(errno)")
            }

            var pathBuffer = [CChar](repeating: 0, count: Self.pidPathCapacity)
            guard proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count)) > 0 else {
                throw SocketDaemonClientError.untrustedDaemon("proc_pidpath failed with errno \(errno)")
            }

            let pathBytes: [UInt8] = pathBuffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
            guard let executablePath = String(bytes: pathBytes, encoding: .utf8) else {
                throw SocketDaemonClientError.untrustedDaemon("proc_pidpath returned invalid utf8")
            }

            return DaemonPeerInfo(
                uid: uid,
                gid: gid,
                pid: pid,
                executablePath: executablePath
            )
        }

        static func validate(
            socketFileDescriptor descriptor: Int32,
            using peerValidator: DaemonPeerValidator?
        ) throws {
            guard let peerValidator else {
                return
            }
            let info = try inspect(socketFileDescriptor: descriptor)
            try peerValidator.validateDaemonPeer(info)
        }
    }
#endif
