import Foundation

#if canImport(Darwin)
    import Darwin
#endif

final class UnixSocketLineTransport: LineTransport {
    #if canImport(Darwin)
        private static let defaultIOTimeout: TimeInterval = 5
        private static let defaultMaxFrameBytes: Int = 1_048_576
        private static let lineFeedByte: UInt8 = 10
        private static let pathTerminatorByte: UInt8 = 0
        private static let readChunkBytes: Int = 0x1000
        private static let singleAddressCapacity: Int = 1
        private static let timevalMicrosecondsPerSecond: Int = 1_000_000

        private let maxFrameBytes: Int
        private let socketFileDescriptor: Int32
        private var bufferedReadData = Data()
    #endif

    convenience init(path: String) throws {
        try self.init(
            path: path,
            maxFrameBytes: Self.defaultMaxFrameBytes,
            ioTimeout: Self.defaultIOTimeout,
            peerValidator: TrustedDaemonPeerValidator.defaultForCurrentProcess()
        )
    }

    #if canImport(Darwin)
        init(
            socketFileDescriptor descriptor: Int32,
            maxFrameBytes: Int = defaultMaxFrameBytes,
            ioTimeout: TimeInterval = defaultIOTimeout,
            peerValidator: DaemonPeerValidator? = nil
        ) throws {
            try Self.validate(maxFrameBytes: maxFrameBytes)
            do {
                try Self.configureTimeouts(
                    for: descriptor,
                    ioTimeout: ioTimeout
                )
                try DaemonPeerInspector.validate(
                    socketFileDescriptor: descriptor,
                    using: peerValidator
                )
            } catch {
                close(descriptor)
                throw error
            }
            self.maxFrameBytes = maxFrameBytes
            socketFileDescriptor = descriptor
        }
    #endif

    init(
        path: String,
        maxFrameBytes: Int,
        ioTimeout: TimeInterval,
        peerValidator: DaemonPeerValidator?
    ) throws {
        #if canImport(Darwin)
            try Self.validate(maxFrameBytes: maxFrameBytes)
            let descriptor: Int32 = socket(AF_UNIX, SOCK_STREAM, 0)
            guard descriptor >= 0 else {
                throw SocketDaemonClientError.connectFailed(errno)
            }

            var address = sockaddr_un()
            address.sun_family = sa_family_t(AF_UNIX)
            var pathBytes: [UInt8] = Array(path.utf8)
            pathBytes.append(Self.pathTerminatorByte)
            let capacity: Int = MemoryLayout.size(ofValue: address.sun_path)
            guard pathBytes.count <= capacity else {
                close(descriptor)
                throw SocketDaemonClientError.pathTooLong(path)
            }
            withUnsafeMutableBytes(of: &address.sun_path) { rawBuffer in
                rawBuffer.copyBytes(from: pathBytes)
            }

            let status: Int32 = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: Self.singleAddressCapacity) { sockaddrPointer in
                    connect(descriptor, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            guard status == 0 else {
                let errnoValue: Int32 = errno
                close(descriptor)
                throw SocketDaemonClientError.connectFailed(errnoValue)
            }
            do {
                try Self.configureTimeouts(
                    for: descriptor,
                    ioTimeout: ioTimeout
                )
                try DaemonPeerInspector.validate(
                    socketFileDescriptor: descriptor,
                    using: peerValidator
                )
            } catch {
                close(descriptor)
                throw error
            }
            self.maxFrameBytes = maxFrameBytes
            socketFileDescriptor = descriptor
        #else
            _ = path
            _ = maxFrameBytes
            _ = ioTimeout
            _ = peerValidator
            throw SocketDaemonClientError.socketUnavailable
        #endif
    }

    #if canImport(Darwin)
        private static func validate(maxFrameBytes: Int) throws {
            guard maxFrameBytes > 0 else {
                throw SocketDaemonClientError.invalidResponse("invalid maximum frame size")
            }
        }

        private static func configureTimeouts(
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

        private static func socketTimeval(from timeout: TimeInterval) -> timeval {
            let totalMicroseconds = max(
                1,
                Int(timeout * TimeInterval(Self.timevalMicrosecondsPerSecond))
            )
            return Darwin.timeval(
                tv_sec: totalMicroseconds / Self.timevalMicrosecondsPerSecond,
                tv_usec: Int32(totalMicroseconds % Self.timevalMicrosecondsPerSecond)
            )
        }

        private static func isTimeout(_ errnoValue: Int32) -> Bool {
            errnoValue == EAGAIN || errnoValue == EWOULDBLOCK
        }

    #endif

    func readLine() throws -> Data {
        #if canImport(Darwin)
            var readBuffer = [UInt8](repeating: 0, count: Self.readChunkBytes)
            while true {
                if let line: Data = try consumeBufferedLine() {
                    return line
                }
                if bufferedReadData.count > maxFrameBytes {
                    throw SocketDaemonClientError.frameTooLarge(maxFrameBytes)
                }
                let bufferCapacity: Int = readBuffer.count
                let count: Int = readBuffer.withUnsafeMutableBytes { rawBuffer -> Int in
                    guard let baseAddress = rawBuffer.baseAddress else {
                        return 0
                    }
                    return Darwin.read(socketFileDescriptor, baseAddress, bufferCapacity)
                }
                if count == 0 {
                    throw SocketDaemonClientError.disconnected
                }
                guard count > 0 else {
                    if Self.isTimeout(errno) {
                        throw SocketDaemonClientError.readTimedOut
                    }
                    throw SocketDaemonClientError.readFailed(errno)
                }
                bufferedReadData.append(contentsOf: readBuffer.prefix(count))
            }
        #else
            throw SocketDaemonClientError.socketUnavailable
        #endif
    }

    func writeLine(_ data: Data) throws {
        #if canImport(Darwin)
            guard data.count <= maxFrameBytes else {
                throw SocketDaemonClientError.frameTooLarge(maxFrameBytes)
            }
            var bytes: [UInt8] = Array(data)
            bytes.append(Self.lineFeedByte)
            var written = 0
            while written < bytes.count {
                let count: Int = bytes.withUnsafeBytes { rawBuffer -> Int in
                    guard let baseAddress: UnsafeRawPointer = rawBuffer.baseAddress else {
                        return 0
                    }
                    return Darwin.write(
                        socketFileDescriptor,
                        baseAddress.advanced(by: written),
                        bytes.count - written
                    )
                }
                guard count > 0 else {
                    if Self.isTimeout(errno) {
                        throw SocketDaemonClientError.writeTimedOut
                    }
                    throw SocketDaemonClientError.writeFailed(errno)
                }
                written += count
            }
        #else
            _ = data
            throw SocketDaemonClientError.socketUnavailable
        #endif
    }

    #if canImport(Darwin)
        private func consumeBufferedLine() throws -> Data? {
            guard let lineFeedIndex: Data.Index = bufferedReadData.firstIndex(of: Self.lineFeedByte) else {
                return nil
            }
            let line = bufferedReadData[..<lineFeedIndex]
            guard line.count <= maxFrameBytes else {
                throw SocketDaemonClientError.frameTooLarge(maxFrameBytes)
            }
            let output = Data(line)
            bufferedReadData.removeSubrange(bufferedReadData.startIndex ... lineFeedIndex)
            return output
        }
    #endif

    deinit {
        #if canImport(Darwin)
            close(socketFileDescriptor)
        #else
            /* Required by SwiftLint. */
        #endif
    }
}
