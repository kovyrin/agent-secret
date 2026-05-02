@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(Darwin)
    import Darwin

    final class UnixSocketLineTransportTests: XCTestCase {
        private static let shortTimeout: TimeInterval = 0.05
        private static let smallFrameBytes: Int = 4
        private static let testFrameBytes: Int = 64

        private static func writeString(_ value: String, to descriptor: Int32) throws {
            let data = Data(value.utf8)
            let written: Int = data.withUnsafeBytes { rawBuffer -> Int in
                guard let baseAddress = rawBuffer.baseAddress else {
                    return 0
                }
                return Darwin.write(descriptor, baseAddress, data.count)
            }
            guard written == data.count else {
                throw SocketDaemonClientError.writeFailed(errno)
            }
        }

        private static func readString(from descriptor: Int32) throws -> String {
            var buffer = [UInt8](repeating: 0, count: Self.testFrameBytes)
            let bufferCapacity: Int = buffer.count
            let count: Int = buffer.withUnsafeMutableBytes { rawBuffer -> Int in
                guard let baseAddress = rawBuffer.baseAddress else {
                    return 0
                }
                return Darwin.read(descriptor, baseAddress, bufferCapacity)
            }
            guard count > 0 else {
                throw SocketDaemonClientError.readFailed(errno)
            }
            guard let output = String(bytes: buffer.prefix(count), encoding: .utf8) else {
                throw SocketDaemonClientError.invalidResponse("invalid utf8 test response")
            }
            return output
        }

        private static func string(from data: Data) throws -> String {
            guard let output = String(bytes: data, encoding: .utf8) else {
                throw SocketDaemonClientError.invalidResponse("invalid utf8 test response")
            }
            return output
        }

        private func makeTransportPair(
            maxFrameBytes: Int? = nil,
            ioTimeout: TimeInterval? = nil
        ) throws -> (transport: UnixSocketLineTransport, peer: Int32) {
            var descriptors = [Int32](repeating: -1, count: 2)
            guard socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else {
                throw SocketDaemonClientError.connectFailed(errno)
            }
            let frameBytes: Int = maxFrameBytes ?? Self.testFrameBytes
            let timeout: TimeInterval = ioTimeout ?? Self.shortTimeout
            do {
                let transport = try UnixSocketLineTransport(
                    socketFileDescriptor: descriptors[0],
                    maxFrameBytes: frameBytes,
                    ioTimeout: timeout
                )
                return (transport, descriptors[1])
            } catch {
                close(descriptors[0])
                close(descriptors[1])
                throw error
            }
        }

        private func assertTransportError(
            _ expected: SocketDaemonClientError,
            _ expression: () throws -> Void
        ) {
            XCTAssertThrowsError(try expression()) { error in
                XCTAssertEqual(error as? SocketDaemonClientError, expected)
            }
        }

        func testReadLineReturnsNormalResponseAndKeepsBufferedLine() throws {
            let pair = try makeTransportPair()
            defer {
                close(pair.peer)
            }

            try Self.writeString("first\nsecond\n", to: pair.peer)

            XCTAssertEqual(try Self.string(from: pair.transport.readLine()), "first")
            XCTAssertEqual(try Self.string(from: pair.transport.readLine()), "second")
        }

        func testReadLineRejectsOversizedFrame() throws {
            let pair = try makeTransportPair(maxFrameBytes: Self.smallFrameBytes)
            defer {
                close(pair.peer)
            }

            try Self.writeString("abcde\n", to: pair.peer)

            assertTransportError(.frameTooLarge(Self.smallFrameBytes)) {
                _ = try pair.transport.readLine()
            }
        }

        func testReadLineTimesOutWhenPeerNeverSendsNewline() throws {
            let pair = try makeTransportPair()
            defer {
                close(pair.peer)
            }

            try Self.writeString("partial", to: pair.peer)

            assertTransportError(.readTimedOut) {
                _ = try pair.transport.readLine()
            }
        }

        func testWriteLineAppendsNewline() throws {
            let pair = try makeTransportPair()
            defer {
                close(pair.peer)
            }

            try pair.transport.writeLine(Data("hello".utf8))

            XCTAssertEqual(try Self.readString(from: pair.peer), "hello\n")
        }

        func testWriteLineRejectsOversizedFrame() throws {
            let pair = try makeTransportPair(maxFrameBytes: Self.smallFrameBytes)
            defer {
                close(pair.peer)
            }

            assertTransportError(.frameTooLarge(Self.smallFrameBytes)) {
                try pair.transport.writeLine(Data("abcde".utf8))
            }
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }
#endif
