import Foundation

#if canImport(Darwin)
    import Darwin
    import Security

    struct SecurityDaemonCodeSignatureChecker: DaemonCodeSignatureChecking {
        private static func runCodesign(arguments: [String]) throws -> String {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
            process.arguments = arguments
            let output = Pipe()
            process.standardOutput = output
            process.standardError = output
            do {
                try process.run()
            } catch {
                throw SocketDaemonClientError.untrustedDaemon(
                    "launch daemon process code signature validation failed: \(error)"
                )
            }
            process.waitUntilExit()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            let text = String(data: data, encoding: .utf8) ?? ""
            guard process.terminationStatus == 0 else {
                throw SocketDaemonClientError.untrustedDaemon(
                    "daemon process code signature validation failed with status \(process.terminationStatus)"
                )
            }
            return text
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
            _ = try Self.runCodesign(arguments: ["--verify", "--strict", "--deep", target])
            let output = try Self.runCodesign(arguments: ["-dv", "--verbose=4", target])
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
