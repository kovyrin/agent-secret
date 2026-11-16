import Foundation

#if canImport(Darwin)
    import Darwin

    extension UnixSocketLineTransport {
        static func openSocket(
            path: String,
            maxFrameBytes: Int,
            ioTimeout: TimeInterval,
            peerValidator: DaemonPeerValidator?
        ) throws -> Int32 {
            try validate(maxFrameBytes: maxFrameBytes)
            let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
            guard descriptor >= 0 else {
                throw SocketDaemonClientError.connectFailed(errno)
            }
            var address = sockaddr_un()
            address.sun_family = sa_family_t(AF_UNIX)
            var pathBytes = Array(path.utf8)
            pathBytes.append(0)
            guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
                close(descriptor)
                throw SocketDaemonClientError.pathTooLong(path)
            }
            withUnsafeMutableBytes(of: &address.sun_path) { rawBuffer in
                rawBuffer.copyBytes(from: pathBytes)
            }
            let status = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                    connect(descriptor, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            guard status == 0 else {
                let errnoValue = errno
                close(descriptor)
                throw SocketDaemonClientError.connectFailed(errnoValue)
            }
            do {
                try configureSocket(for: descriptor, ioTimeout: ioTimeout)
                try validatePeer(socketFileDescriptor: descriptor, using: peerValidator)
            } catch {
                close(descriptor)
                throw error
            }
            return descriptor
        }

        static func validate(maxFrameBytes: Int) throws {
            guard maxFrameBytes > 0 else {
                throw SocketDaemonClientError.invalidResponse("invalid maximum frame size")
            }
        }

        static func validatePeer(
            socketFileDescriptor descriptor: Int32,
            using peerValidator: DaemonPeerValidator?
        ) throws {
            do {
                try DaemonPeerInspector.validate(socketFileDescriptor: descriptor, using: peerValidator)
            } catch let error as DaemonTrustError {
                throw SocketDaemonClientError.untrustedDaemon(error.message)
            }
        }

        static func configureSocket(
            for descriptor: Int32,
            ioTimeout: TimeInterval
        ) throws {
            let descriptorFlags = fcntl(descriptor, F_GETFD)
            guard descriptorFlags >= 0, fcntl(descriptor, F_SETFD, descriptorFlags | FD_CLOEXEC) == 0 else {
                throw SocketDaemonClientError.connectFailed(errno)
            }
            try configureTimeout(
                for: descriptor,
                option: SO_RCVTIMEO,
                timeout: ioTimeout,
                error: SocketDaemonClientError.readFailed
            )
            try configureTimeout(
                for: descriptor,
                option: SO_SNDTIMEO,
                timeout: ioTimeout,
                error: SocketDaemonClientError.writeFailed
            )
            try configureNoSigPipe(for: descriptor)
        }

        static func isTimeout(_ errnoValue: Int32) -> Bool {
            errnoValue == EAGAIN || errnoValue == EWOULDBLOCK
        }

        private static func configureTimeout(
            for descriptor: Int32,
            option: Int32,
            timeout: TimeInterval,
            error: (Int32) -> SocketDaemonClientError
        ) throws {
            var value = socketTimeval(from: timeout)
            let status: Int32 = withUnsafePointer(to: &value) { pointer in
                pointer.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<timeval>.size) { rawPointer in
                    setsockopt(
                        descriptor,
                        SOL_SOCKET,
                        option,
                        rawPointer,
                        socklen_t(MemoryLayout<timeval>.size)
                    )
                }
            }
            guard status == 0 else {
                throw error(errno)
            }
        }

        private static func configureNoSigPipe(for descriptor: Int32) throws {
            var value: Int32 = 1
            let status: Int32 = withUnsafePointer(to: &value) { pointer in
                pointer.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout<Int32>.size) { rawPointer in
                    setsockopt(
                        descriptor,
                        SOL_SOCKET,
                        SO_NOSIGPIPE,
                        rawPointer,
                        socklen_t(MemoryLayout<Int32>.size)
                    )
                }
            }
            guard status == 0 else {
                throw SocketDaemonClientError.writeFailed(errno)
            }
        }

        private static func socketTimeval(from timeout: TimeInterval) -> timeval {
            let microsecondsPerSecond = 1_000_000
            let totalMicroseconds = max(
                1,
                Int(timeout * TimeInterval(microsecondsPerSecond))
            )
            return Darwin.timeval(
                tv_sec: totalMicroseconds / microsecondsPerSecond,
                tv_usec: Int32(totalMicroseconds % microsecondsPerSecond)
            )
        }
    }
#endif
