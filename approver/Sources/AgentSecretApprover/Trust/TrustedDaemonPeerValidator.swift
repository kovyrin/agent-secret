import Foundation

#if canImport(Darwin)
    import Darwin

    struct TrustedDaemonPeerValidator: DaemonPeerValidator {
        private struct TrustedExecutable {
            let path: String
            let fileIdentity: FileIdentity

            func validateCurrentFile() throws {
                let current = try FileIdentity(path: path)
                guard current == fileIdentity else {
                    throw DaemonTrustError.untrustedDaemon(
                        "daemon executable changed since trust snapshot"
                    )
                }
            }
        }

        private struct FileIdentity: Equatable {
            private static let permissionModeMask: mode_t = 0o777
            private static let nanosecondsPerSecond: Int64 = 1_000_000_000

            let device: UInt64
            let inode: UInt64
            let mode: UInt32
            let size: Int64
            let modTimeUnixNanoseconds: Int64
            let changeTimeUnixNanoseconds: Int64

            init(path: String) throws {
                var statBuffer = stat()
                guard stat(path, &statBuffer) == 0 else {
                    throw DaemonTrustError.untrustedDaemon(
                        "stat trusted daemon executable failed with errno \(errno)"
                    )
                }
                guard (statBuffer.st_mode & S_IFMT) == S_IFREG else {
                    throw DaemonTrustError.untrustedDaemon(
                        "trusted daemon path is not a regular file"
                    )
                }
                guard (statBuffer.st_mode & S_IXUSR) != 0 else {
                    throw DaemonTrustError.untrustedDaemon(
                        "trusted daemon path is not executable"
                    )
                }
                device = UInt64(statBuffer.st_dev)
                inode = UInt64(statBuffer.st_ino)
                mode = UInt32(statBuffer.st_mode & Self.permissionModeMask)
                size = Int64(statBuffer.st_size)
                modTimeUnixNanoseconds = Self.unixNanoseconds(statBuffer.st_mtimespec)
                changeTimeUnixNanoseconds = Self.unixNanoseconds(statBuffer.st_ctimespec)
            }

            private static func unixNanoseconds(_ timestamp: timespec) -> Int64 {
                Int64(timestamp.tv_sec) * nanosecondsPerSecond + Int64(timestamp.tv_nsec)
            }
        }

        private static let daemonHelperPathComponents: [String] = [
            "Contents",
            "Library",
            "Helpers",
            "AgentSecretDaemon.app",
            "Contents",
            "MacOS",
            "Agent Secret"
        ]
        private static let expectedTeamIDKey: String = "AgentSecretExpectedTeamID"
        private static let developmentExpectedTeamID: String = "-"

        private let expectedTeamID: String
        private let signatureChecker: DaemonCodeSignatureChecking
        private let trustedExecutables: [TrustedExecutable]
        private let candidateErrors: [String]

        init(
            expectedExecutablePaths: [String],
            expectedTeamID: String = Self.configuredExpectedTeamID(),
            signatureChecker: DaemonCodeSignatureChecking = SecurityDaemonCodeSignatureChecker()
        ) {
            self.expectedTeamID = expectedTeamID.trimmingCharacters(in: .whitespacesAndNewlines)
            self.signatureChecker = signatureChecker

            var candidateErrors: [String] = []
            var seen = Set<String>()
            trustedExecutables = expectedExecutablePaths.compactMap { path in
                let normalized = Self.comparablePath(path)
                guard !normalized.isEmpty, seen.insert(normalized).inserted else {
                    return nil
                }
                do {
                    let identity = try FileIdentity(path: normalized)
                    return TrustedExecutable(path: normalized, fileIdentity: identity)
                } catch {
                    candidateErrors.append("\(normalized): \(error)")
                    return nil
                }
            }
            self.candidateErrors = candidateErrors
        }

        private static func isInsideAppBundle(_ path: String) -> Bool {
            containingAppBundlePath(path) != nil
        }

        static func defaultForCurrentProcess() -> Self {
            Self(expectedExecutablePaths: defaultTrustedDaemonPaths())
        }

        static func defaultTrustedDaemonPaths(
            mainBundle: Bundle = .main,
            arguments: [String] = CommandLine.arguments
        ) -> [String] {
            var candidates: [String] = []
            let executablePath = mainBundle.executableURL?.path ?? arguments.first ?? ""
            if let appBundlePath = containingAppBundlePath(executablePath) {
                candidates.append(daemonHelperPath(inAppBundle: appBundlePath))
            }
            if !executablePath.isEmpty {
                candidates.append(
                    URL(fileURLWithPath: executablePath)
                        .deletingLastPathComponent()
                        .appendingPathComponent("agent-secretd")
                        .path
                )
            }
            return uniqueComparablePaths(candidates)
        }

        private static func daemonHelperPath(inAppBundle appBundlePath: String) -> String {
            var url = URL(fileURLWithPath: appBundlePath)
            for component in daemonHelperPathComponents {
                url.appendPathComponent(component)
            }
            return url.path
        }

        private static func containingAppBundlePath(_ path: String) -> String? {
            var url = URL(fileURLWithPath: path).deletingLastPathComponent()
            while url.path != "/" {
                if url.pathExtension == "app" {
                    return url.path
                }
                url.deleteLastPathComponent()
            }
            return nil
        }

        private static func uniqueComparablePaths(_ paths: [String]) -> [String] {
            var seen = Set<String>()
            var output: [String] = []
            for path in paths {
                let normalized = comparablePath(path)
                if !normalized.isEmpty, seen.insert(normalized).inserted {
                    output.append(normalized)
                }
            }
            return output
        }

        private static func comparablePath(_ path: String) -> String {
            guard !path.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                return ""
            }
            return URL(fileURLWithPath: path)
                .standardizedFileURL
                .resolvingSymlinksInPath()
                .path
        }

        private static func configuredExpectedTeamID() -> String {
            guard let value = Bundle.main.object(forInfoDictionaryKey: expectedTeamIDKey) as? String else {
                return ""
            }
            return value.trimmingCharacters(in: .whitespacesAndNewlines)
        }

        private static func validatePeerCredentials(_ info: DaemonPeerInfo) throws {
            guard info.uid == getuid() else {
                throw DaemonTrustError.untrustedDaemon("daemon uid does not match current user")
            }
            guard info.gid == getgid() else {
                throw DaemonTrustError.untrustedDaemon("daemon gid does not match current user")
            }
            guard info.pid > 0 else {
                throw DaemonTrustError.untrustedDaemon("daemon pid is unavailable")
            }
        }

        func validateDaemonPeer(_ info: DaemonPeerInfo) throws {
            try Self.validatePeerCredentials(info)
            let got = Self.comparablePath(info.executablePath)
            guard !got.isEmpty else {
                throw DaemonTrustError.untrustedDaemon("daemon executable path is unavailable")
            }
            guard !trustedExecutables.isEmpty else {
                var message = "no trusted daemon executables configured"
                if !candidateErrors.isEmpty {
                    message += ": " + candidateErrors.joined(separator: "; ")
                }
                throw DaemonTrustError.untrustedDaemon(message)
            }
            guard let trusted = trustedExecutables.first(where: { $0.path == got }) else {
                throw DaemonTrustError.untrustedDaemon("daemon executable is not trusted")
            }

            try trusted.validateCurrentFile()
            if expectedTeamID.isEmpty, Self.isInsideAppBundle(trusted.path) {
                throw DaemonTrustError.untrustedDaemon(
                    "expected Developer ID Team ID is required for daemon signature validation"
                )
            }
            if !expectedTeamID.isEmpty, expectedTeamID != Self.developmentExpectedTeamID {
                let staticTeamID = try signatureChecker.staticCodeTeamID(for: trusted.path)
                guard staticTeamID == expectedTeamID else {
                    throw DaemonTrustError.untrustedDaemon("daemon Team ID does not match")
                }
                let processTeamID = try signatureChecker.processTeamID(for: info.pid)
                guard processTeamID == expectedTeamID else {
                    throw DaemonTrustError.untrustedDaemon("daemon process Team ID does not match")
                }
            }
        }
    }
#endif
