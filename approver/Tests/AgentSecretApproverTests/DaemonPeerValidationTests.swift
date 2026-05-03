@testable import AgentSecretApprover
import Foundation
import XCTest

#if canImport(Darwin)
    import Darwin

    final class DaemonPeerValidationTests: XCTestCase {
        private final class FakeSignatureChecker: DaemonCodeSignatureChecking {
            var staticTeamIDResult: Result<String, Error> = .success("TEAMID")
            var processTeamIDResult: Result<String, Error> = .success("TEAMID")
            private(set) var processPIDs: [pid_t] = []

            func staticCodeTeamID(for _: String) throws -> String {
                try staticTeamIDResult.get()
            }

            func processTeamID(for pid: pid_t) throws -> String {
                processPIDs.append(pid)
                return try processTeamIDResult.get()
            }

            deinit {
                /* Required by SwiftLint. */
            }
        }

        private final class UnixSocketServer: @unchecked Sendable {
            let path: String
            private let descriptor: Int32

            init(path: String) throws {
                self.path = path
                descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
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

                let bindStatus = withUnsafePointer(to: &address) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                        Darwin.bind(descriptor, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
                    }
                }
                guard bindStatus == 0 else {
                    close(descriptor)
                    throw SocketDaemonClientError.connectFailed(errno)
                }
                guard listen(descriptor, 1) == 0 else {
                    close(descriptor)
                    throw SocketDaemonClientError.connectFailed(errno)
                }
            }

            func acceptOneConnection(holdOpenUntil release: DispatchSemaphore? = nil) {
                let client = accept(descriptor, nil, nil)
                if client >= 0 {
                    if let release {
                        _ = release.wait(timeout: .now() + 5)
                    }
                    close(client)
                }
            }

            deinit {
                close(descriptor)
                unlink(path)
            }
        }

        private static func currentExecutablePath() throws -> String {
            try XCTUnwrap(Bundle.main.executableURL?.path)
        }

        private static func currentPeerInfo(
            uid: uid_t = getuid(),
            gid: gid_t = getgid(),
            pid: pid_t = getpid()
        ) throws -> DaemonPeerInfo {
            try DaemonPeerInfo(
                uid: uid,
                gid: gid,
                pid: pid,
                executablePath: currentExecutablePath()
            )
        }

        private static func makeServer(testCase: XCTestCase) throws -> UnixSocketServer {
            let directory = URL(fileURLWithPath: "/tmp")
                .appendingPathComponent("agent-secret-swift-tests-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let path = directory.appendingPathComponent("daemon.sock").path
            testCase.addTeardownBlock {
                unlink(path)
                try? FileManager.default.removeItem(at: directory)
            }
            return try UnixSocketServer(path: path)
        }

        func testTrustedDaemonValidatorAcceptsCurrentExecutablePeer() throws {
            var descriptors = [Int32](repeating: -1, count: 2)
            XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors), 0)
            defer {
                close(descriptors[0])
                close(descriptors[1])
            }

            let info = try DaemonPeerInspector.inspect(socketFileDescriptor: descriptors[0])
            let validator = try TrustedDaemonPeerValidator(
                expectedExecutablePaths: [Self.currentExecutablePath()]
            )

            XCTAssertNoThrow(try validator.validateDaemonPeer(info))
        }

        func testTrustedDaemonValidatorRejectsDifferentUID() throws {
            let validator = try TrustedDaemonPeerValidator(
                expectedExecutablePaths: [Self.currentExecutablePath()]
            )
            let info = try Self.currentPeerInfo(uid: getuid() + 1)

            XCTAssertThrowsError(try validator.validateDaemonPeer(info)) { error in
                XCTAssertEqual(
                    error as? SocketDaemonClientError,
                    .untrustedDaemon("daemon uid does not match current user")
                )
            }
        }

        func testTrustedDaemonValidatorRejectsDifferentGID() throws {
            let validator = try TrustedDaemonPeerValidator(
                expectedExecutablePaths: [Self.currentExecutablePath()]
            )
            let info = try Self.currentPeerInfo(gid: getgid() + 1)

            XCTAssertThrowsError(try validator.validateDaemonPeer(info)) { error in
                XCTAssertEqual(
                    error as? SocketDaemonClientError,
                    .untrustedDaemon("daemon gid does not match current user")
                )
            }
        }

        func testTrustedDaemonValidatorRejectsMissingPID() throws {
            let validator = try TrustedDaemonPeerValidator(
                expectedExecutablePaths: [Self.currentExecutablePath()]
            )
            let info = try Self.currentPeerInfo(pid: 0)

            XCTAssertThrowsError(try validator.validateDaemonPeer(info)) { error in
                XCTAssertEqual(
                    error as? SocketDaemonClientError,
                    .untrustedDaemon("daemon pid is unavailable")
                )
            }
        }

        func testTrustedDaemonValidatorRejectsUnexpectedExecutablePeer() throws {
            var descriptors = [Int32](repeating: -1, count: 2)
            XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors), 0)
            defer {
                close(descriptors[0])
                close(descriptors[1])
            }

            let info = try DaemonPeerInspector.inspect(socketFileDescriptor: descriptors[0])
            let validator = TrustedDaemonPeerValidator(expectedExecutablePaths: ["/bin/ls"])

            XCTAssertThrowsError(try validator.validateDaemonPeer(info)) { error in
                XCTAssertEqual(
                    error as? SocketDaemonClientError,
                    .untrustedDaemon("daemon executable is not trusted")
                )
            }
        }

        func testTrustedDaemonValidatorChecksProcessTeamIDWhenExpected() throws {
            let checker = FakeSignatureChecker()
            let validator = try TrustedDaemonPeerValidator(
                expectedExecutablePaths: [Self.currentExecutablePath()],
                expectedTeamID: "TEAMID",
                signatureChecker: checker
            )
            let info = try Self.currentPeerInfo()

            XCTAssertNoThrow(try validator.validateDaemonPeer(info))
            XCTAssertEqual(checker.processPIDs, [getpid()])
        }

        func testTrustedDaemonValidatorRejectsMismatchedProcessTeamID() throws {
            let checker = FakeSignatureChecker()
            checker.processTeamIDResult = .success("OTHERTEAM")
            let validator = try TrustedDaemonPeerValidator(
                expectedExecutablePaths: [Self.currentExecutablePath()],
                expectedTeamID: "TEAMID",
                signatureChecker: checker
            )
            let info = try Self.currentPeerInfo()

            XCTAssertThrowsError(try validator.validateDaemonPeer(info)) { error in
                XCTAssertEqual(
                    error as? SocketDaemonClientError,
                    .untrustedDaemon("daemon process Team ID does not match")
                )
            }
            XCTAssertEqual(checker.processPIDs, [getpid()])
        }

        func testPathTransportRejectsSocketBeforeProtocolWhenPeerIsUntrusted() throws {
            let server = try Self.makeServer(testCase: self)
            let releaseConnection = DispatchSemaphore(value: 0)
            let acceptThread = Thread {
                server.acceptOneConnection(holdOpenUntil: releaseConnection)
            }
            acceptThread.start()
            defer { releaseConnection.signal() }

            XCTAssertThrowsError(try UnixSocketLineTransport(path: server.path)) { error in
                guard case .untrustedDaemon = error as? SocketDaemonClientError else {
                    return XCTFail("expected untrusted daemon error, got \(error)")
                }
            }
        }

        func testPathTransportCanTrustCurrentExecutableForLocalPeer() throws {
            let server = try Self.makeServer(testCase: self)
            let releaseConnection = DispatchSemaphore(value: 0)
            let acceptThread = Thread {
                server.acceptOneConnection(holdOpenUntil: releaseConnection)
            }
            acceptThread.start()
            defer { releaseConnection.signal() }

            let validator = try TrustedDaemonPeerValidator(
                expectedExecutablePaths: [Self.currentExecutablePath()]
            )
            let transport = try UnixSocketLineTransport(
                path: server.path,
                maxFrameBytes: 64,
                ioTimeout: 0.05,
                peerValidator: validator
            )
            releaseConnection.signal()

            XCTAssertThrowsError(try transport.readLine()) { error in
                XCTAssertEqual(error as? SocketDaemonClientError, .disconnected)
            }
        }

        deinit {
            /* Required by SwiftLint. */
        }
    }
#endif
