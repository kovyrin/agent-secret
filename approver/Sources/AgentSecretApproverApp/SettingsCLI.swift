import Foundation

enum SettingsCLI {
    static var executable: URL {
        Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/bin/agent-secret")
    }

    static var status: SettingsState.CLIStatus {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let candidates = [home.appendingPathComponent(".local/bin/agent-secret")]
            + ["/opt/homebrew/bin/agent-secret", "/usr/local/bin/agent-secret"].map { URL(fileURLWithPath: $0) }
        return status(executable: executable, candidates: candidates)
    }

    static func status(executable: URL, candidates: [URL]) -> SettingsState.CLIStatus {
        let files = FileManager.default
        guard files.isExecutableFile(atPath: executable.path) else {
            return .unavailable
        }
        for candidate in candidates {
            let isLink = (try? files.destinationOfSymbolicLink(atPath: candidate.path)) != nil
            guard isLink || files.fileExists(atPath: candidate.path) else { continue }
            let matchesBundle = candidate.resolvingSymlinksInPath() == executable.resolvingSymlinksInPath()
            if files.isExecutableFile(atPath: candidate.path), matchesBundle {
                return .installed
            }
            return .repairNeeded
        }
        return .missing
    }
}
