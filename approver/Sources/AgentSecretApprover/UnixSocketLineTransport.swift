import Foundation

#if canImport(Darwin)
import Darwin
#endif

internal final class UnixSocketLineTransport: LineTransport {
    #if canImport(Darwin)
    private static let lineFeedByte: UInt8 = 10
    private static let pathTerminatorByte: UInt8 = 0
    private static let singleAddressCapacity: Int = 1
    private static let singleByteCount: Int = 1

    private let socketFileDescriptor: Int32
    #endif

    internal init(path: String) throws {
        #if canImport(Darwin)
        let descriptor: Int32 = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw SocketDaemonClientError.connectFailed(errno)
        }
        socketFileDescriptor = descriptor

        var address: sockaddr_un = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        var pathBytes: [UInt8] = Array(path.utf8)
        pathBytes.append(Self.pathTerminatorByte)
        let capacity: Int = MemoryLayout.size(ofValue: address.sun_path)
        guard pathBytes.count <= capacity else {
            close(socketFileDescriptor)
            throw SocketDaemonClientError.pathTooLong(path)
        }
        withUnsafeMutableBytes(of: &address.sun_path) { rawBuffer in
            rawBuffer.copyBytes(from: pathBytes)
        }

        let status: Int32 = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: Self.singleAddressCapacity) { sockaddrPointer in
                connect(socketFileDescriptor, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard status == 0 else {
            let errnoValue: Int32 = errno
            close(socketFileDescriptor)
            throw SocketDaemonClientError.connectFailed(errnoValue)
        }
        #else
        _ = path
        throw SocketDaemonClientError.socketUnavailable
        #endif
    }

    internal func readLine() throws -> Data {
        #if canImport(Darwin)
        var output: Data = Data()
        var byte: UInt8 = 0
        while true {
            let count: Int = Darwin.read(socketFileDescriptor, &byte, Self.singleByteCount)
            if count == 0 {
                throw SocketDaemonClientError.disconnected
            }
            guard count > 0 else {
                throw SocketDaemonClientError.readFailed(errno)
            }
            if byte == Self.lineFeedByte {
                return output
            }
            output.append(byte)
        }
        #else
        throw SocketDaemonClientError.socketUnavailable
        #endif
    }

    internal func writeLine(_ data: Data) throws {
        #if canImport(Darwin)
        var bytes: [UInt8] = Array(data)
        bytes.append(Self.lineFeedByte)
        var written: Int = 0
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
                throw SocketDaemonClientError.writeFailed(errno)
            }
            written += count
        }
        #else
        _ = data
        throw SocketDaemonClientError.socketUnavailable
        #endif
    }

    deinit {
        #if canImport(Darwin)
        close(socketFileDescriptor)
        #else
        /* Required by SwiftLint. */
        #endif
    }
}
