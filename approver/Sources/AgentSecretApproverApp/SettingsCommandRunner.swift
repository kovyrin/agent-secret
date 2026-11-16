// swiftformat:options --decimalgrouping 3,3
import Darwin
import Foundation

enum SettingsCommandRunner {
    struct Result {
        let output: String
        let succeeded: Bool
    }

    private static let outputLimit = 65_536
    private static let shutdownTimeout: TimeInterval = 0.2

    static func run(executable: URL, arguments: [String], timeout: TimeInterval) async -> Result {
        await Task.detached(priority: .utility) {
            execute(executable: executable, arguments: arguments, timeout: timeout)
        }.value
    }

    private static func execute(executable: URL, arguments: [String], timeout: TimeInterval) -> Result {
        let files = FileManager.default
        let directory = files.temporaryDirectory.appendingPathComponent("agent-secret-settings-\(UUID().uuidString)")
        defer { try? files.removeItem(at: directory) }
        do {
            try files.createDirectory(
                at: directory,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: 0o700]
            )
            let output = directory.appendingPathComponent("output")
            guard files.createFile(atPath: output.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
                return Result(output: "Could not prepare command output. Try again.", succeeded: false)
            }
            let handle = try FileHandle(forWritingTo: output)
            defer { try? handle.close() }
            let process = Process()
            process.executableURL = executable
            process.arguments = arguments
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = handle
            process.standardError = handle
            let termination = DispatchSemaphore(value: 0)
            process.terminationHandler = { _ in termination.signal() }
            try process.run()
            let timedOut = termination.wait(timeout: .now() + timeout) == .timedOut
            if timedOut {
                process.terminate()
                if termination.wait(timeout: .now() + shutdownTimeout) == .timedOut {
                    kill(process.processIdentifier, SIGKILL)
                    _ = termination.wait(timeout: .now() + shutdownTimeout)
                }
            }
            var text = try readOutput(output)
            if timedOut {
                text += "\nThe command timed out. Close these details and try again."
            } else if text.isEmpty {
                text = process.terminationStatus == 0 ? "Command completed." : "The command failed. Try again."
            }
            return Result(output: text, succeeded: !timedOut && process.terminationStatus == 0)
        } catch {
            return Result(output: "Could not run the bundled command: \(error.localizedDescription)", succeeded: false)
        }
    }

    private static func readOutput(_ url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: outputLimit + 1) ?? Data()
        var output = (String(bytes: data.prefix(outputLimit), encoding: .utf8) ?? "Command output was not valid UTF-8.")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if data.count > outputLimit { output += "\n[Output truncated.]" }
        return output
    }
}
