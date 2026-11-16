import Foundation

#if canImport(Darwin)
    import AgentSecretMachAuth
    import CryptoKit
#endif

#if canImport(Darwin)
    import Darwin
#endif

final class UnixSocketLineTransport: LineTransport {
    #if canImport(Darwin)
        private static let defaultIOTimeout: TimeInterval = 5
        private static let defaultMaxFrameBytes: Int = 1_048_576
        private static let lineFeedByte: UInt8 = 10
        private static let readChunkBytes: Int = 0x1000

        private let maxFrameBytes: Int
        private var socketFileDescriptor: Int32
        private var bufferedReadData = Data()
        var authPortName: String?
    #endif

    convenience init(path: String) throws {
        try self.init(
            path: path,
            maxFrameBytes: Self.defaultMaxFrameBytes,
            ioTimeout: Self.defaultIOTimeout,
            peerValidator: TrustedDaemonPeerValidator.defaultForCurrentProcess(),
            requireMessageAuth: true
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
                try Self.configureSocket(
                    for: descriptor,
                    ioTimeout: ioTimeout
                )
                try Self.validatePeer(
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
        peerValidator: DaemonPeerValidator?,
        requireMessageAuth: Bool = true
    ) throws {
        #if canImport(Darwin)
            let descriptor = try Self.openSocket(
                path: path, maxFrameBytes: maxFrameBytes, ioTimeout: ioTimeout, peerValidator: peerValidator
            )
            self.maxFrameBytes = maxFrameBytes
            socketFileDescriptor = descriptor
            if requireMessageAuth {
                do {
                    try beginMessageAuth()
                } catch {
                    close(descriptor)
                    socketFileDescriptor = -1
                    throw error
                }
            }
        #else
            _ = path
            _ = maxFrameBytes
            _ = ioTimeout
            _ = peerValidator
            _ = requireMessageAuth
            throw SocketDaemonClientError.socketUnavailable
        #endif
    }

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
            if let authPortName {
                let digest = SHA256.hash(data: data)
                let status = authPortName.withCString { name in
                    digest.withUnsafeBytes { bytes in
                        AgentSecretSendMachAuth(name, bytes.bindMemory(to: UInt8.self).baseAddress)
                    }
                }
                guard status == 0 else {
                    throw SocketDaemonClientError.writeFailed(EIO)
                }
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
            if socketFileDescriptor >= 0 {
                close(socketFileDescriptor)
            }
        #endif
    }
}
