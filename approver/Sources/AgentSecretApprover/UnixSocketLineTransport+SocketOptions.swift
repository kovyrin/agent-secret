import Foundation

#if canImport(Darwin)
    import Darwin

    extension UnixSocketLineTransport {
        static func configureSocket(
            for descriptor: Int32,
            ioTimeout: TimeInterval
        ) throws {
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
