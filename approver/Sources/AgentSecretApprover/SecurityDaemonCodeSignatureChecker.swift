import Foundation

#if canImport(Darwin)
    import Security

    struct SecurityDaemonCodeSignatureChecker: DaemonCodeSignatureChecking {
        private let codesignRunner: CodeSignatureProcessRunning
        private let codesignTimeout: TimeInterval

        init(
            codesignRunner: CodeSignatureProcessRunning = FoundationCodeSignatureProcessRunner(),
            codesignTimeout: TimeInterval = 2
        ) {
            self.codesignRunner = codesignRunner
            self.codesignTimeout = codesignTimeout
        }

        private static func teamID(forStaticCode code: SecStaticCode) throws -> String {
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

        private func runCodesign(arguments: [String]) throws -> String {
            let result = try codesignRunner.run(
                executableURL: URL(fileURLWithPath: "/usr/bin/codesign"),
                arguments: arguments,
                timeout: codesignTimeout
            )
            guard result.terminationStatus == 0 else {
                throw SocketDaemonClientError.untrustedDaemon(
                    "daemon process code signature validation failed with status \(result.terminationStatus)"
                )
            }
            return result.output
        }

        func staticCodeTeamID(for path: String) throws -> String {
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

            return try Self.teamID(forStaticCode: code)
        }

        func processTeamID(for pid: pid_t) throws -> String {
            let target = "+\(pid)"
            _ = try runCodesign(arguments: ["--verify", "--strict", "--deep", target])
            let output = try runCodesign(arguments: ["-dv", "--verbose=4", target])
            for line in output.components(separatedBy: .newlines) {
                let trimmedLine = line.trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmedLine.hasPrefix("TeamIdentifier=") {
                    let teamID = String(trimmedLine.dropFirst("TeamIdentifier=".count))
                    guard !teamID.isEmpty else {
                        throw SocketDaemonClientError.untrustedDaemon("daemon code signature has no Team ID")
                    }
                    return teamID
                }
            }
            throw SocketDaemonClientError.untrustedDaemon("daemon code signature has no Team ID")
        }
    }
#endif
