import Foundation

#if canImport(Darwin)
    import Darwin
    import Security

    struct TrustedDaemonPeerValidator: DaemonPeerValidator {
        private struct TrustedExecutable {
            let path: String
            let fileIdentity: FileIdentity

            func validateCurrentFile() throws {
                let current = try FileIdentity(path: path)
                guard current == fileIdentity else {
                    throw SocketDaemonClientError.untrustedDaemon(
                        "daemon executable changed since trust snapshot"
                    )
                }
            }
        }

        private struct FileIdentity: Equatable {
            let device: UInt64
            let inode: UInt64

            init(path: String) throws {
                var statBuffer = stat()
                guard stat(path, &statBuffer) == 0 else {
                    throw SocketDaemonClientError.untrustedDaemon(
                        "stat trusted daemon executable failed with errno \(errno)"
                    )
                }
                guard (statBuffer.st_mode & S_IFMT) == S_IFREG else {
                    throw SocketDaemonClientError.untrustedDaemon(
                        "trusted daemon path is not a regular file"
                    )
                }
                guard (statBuffer.st_mode & S_IXUSR) != 0 else {
                    throw SocketDaemonClientError.untrustedDaemon(
                        "trusted daemon path is not executable"
                    )
                }
                device = UInt64(statBuffer.st_dev)
                inode = UInt64(statBuffer.st_ino)
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

        private let expectedTeamID: String
        private let trustedExecutables: [TrustedExecutable]

        init(expectedExecutablePaths: [String], expectedTeamID: String = Self.configuredExpectedTeamID()) {
            self.expectedTeamID = expectedTeamID.trimmingCharacters(in: .whitespacesAndNewlines)

            var seen = Set<String>()
            trustedExecutables = expectedExecutablePaths.compactMap { path in
                let normalized = Self.comparablePath(path)
                guard !normalized.isEmpty, seen.insert(normalized).inserted else {
                    return nil
                }
                guard let identity = try? FileIdentity(path: normalized) else {
                    return nil
                }
                return TrustedExecutable(path: normalized, fileIdentity: identity)
            }
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

        private static func codeSignatureTeamID(for path: String) throws -> String {
            var staticCode: SecStaticCode?
            let createStatus = SecStaticCodeCreateWithPath(
                URL(fileURLWithPath: path) as CFURL,
                SecCSFlags(),
                &staticCode
            )
            guard createStatus == errSecSuccess, let code = staticCode else {
                throw SocketDaemonClientError.untrustedDaemon(
                    "load daemon code signature failed with status \(createStatus)"
                )
            }

            let checkStatus = SecStaticCodeCheckValidity(
                code,
                SecCSFlags(rawValue: kSecCSStrictValidate),
                nil
            )
            guard checkStatus == errSecSuccess else {
                throw SocketDaemonClientError.untrustedDaemon(
                    "daemon code signature validation failed with status \(checkStatus)"
                )
            }

            var information: CFDictionary?
            let copyStatus = SecCodeCopySigningInformation(
                code,
                SecCSFlags(rawValue: kSecCSSigningInformation),
                &information
            )
            guard copyStatus == errSecSuccess, let dictionary = information as? [String: Any] else {
                throw SocketDaemonClientError.untrustedDaemon(
                    "read daemon code signature failed with status \(copyStatus)"
                )
            }
            guard let teamID = dictionary[kSecCodeInfoTeamIdentifier as String] as? String else {
                throw SocketDaemonClientError.untrustedDaemon("daemon code signature has no Team ID")
            }
            guard !teamID.isEmpty else {
                throw SocketDaemonClientError.untrustedDaemon("daemon code signature has no Team ID")
            }
            return teamID
        }

        func validateDaemonPeer(_ info: DaemonPeerInfo) throws {
            let got = Self.comparablePath(info.executablePath)
            guard !got.isEmpty else {
                throw SocketDaemonClientError.untrustedDaemon("daemon executable path is unavailable")
            }
            guard !trustedExecutables.isEmpty else {
                throw SocketDaemonClientError.untrustedDaemon("no trusted daemon executables configured")
            }
            guard let trusted = trustedExecutables.first(where: { $0.path == got }) else {
                throw SocketDaemonClientError.untrustedDaemon("daemon executable is not trusted")
            }

            try trusted.validateCurrentFile()
            if !expectedTeamID.isEmpty {
                let teamID = try Self.codeSignatureTeamID(for: trusted.path)
                guard teamID == expectedTeamID else {
                    throw SocketDaemonClientError.untrustedDaemon("daemon Team ID does not match")
                }
            }
        }
    }
#endif
