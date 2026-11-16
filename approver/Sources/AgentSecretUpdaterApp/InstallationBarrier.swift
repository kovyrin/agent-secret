import Darwin
import Foundation
import Security

/// Uses the same installation-directory lock as the broker and Homebrew.
/// The marker survives updater termination while Sparkle's installer can still run.
final class InstallationBarrier {
    enum Failure: Error {
        case unsupportedLocation
        case busy
        case recoveryRequired
    }

    private struct Transaction: Codable {
        let version: String
        let boot: String
    }

    private static let markerName = ".agent-secret-update"
    private static let maxMarkerBytes = 0x4000
    private let hostURL: URL
    private let parentURL: URL
    private let markerURL: URL
    private var lock: FileHandle?

    init(hostURL: URL) {
        self.hostURL = hostURL.resolvingSymlinksInPath()
        parentURL = self.hostURL.deletingLastPathComponent()
        markerURL = parentURL.appendingPathComponent(Self.markerName)
    }

    private static func bootSession() -> String? {
        var size = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 1 else {
            return nil
        }
        var data = Data(count: size)
        let status = data.withUnsafeMutableBytes { buffer in
            sysctlbyname("kern.bootsessionuuid", buffer.baseAddress, &size, nil, 0)
        }
        guard status == 0 else {
            return nil
        }
        return String(data: data.prefix(size - 1), encoding: .utf8)
    }

    func verifyLocation() throws {
        let userApplications = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Applications").resolvingSymlinksInPath()
        var filesystem = statfs()
        guard
            hostURL.lastPathComponent == "Agent Secret.app",
            parentURL.path == "/Applications" || parentURL.path == userApplications.path,
            statfs(parentURL.path, &filesystem) == 0,
            filesystem.f_flags & UInt32(MNT_LOCAL) != 0,
            FileManager.default.isWritableFile(atPath: parentURL.path),
            FileManager.default.isWritableFile(atPath: hostURL.path)
        else {
            throw Failure.unsupportedLocation
        }
    }

    func begin(version: String) throws {
        let directory = try lockDirectory()
        var existing = stat()
        guard lstat(markerURL.path, &existing) != 0, errno == ENOENT else {
            throw Failure.recoveryRequired
        }
        guard let boot = Self.bootSession() else {
            throw Failure.recoveryRequired
        }
        let data = try JSONEncoder().encode(Transaction(version: version, boot: boot))
        let staged = parentURL.appendingPathComponent(".agent-secret-update-\(UUID().uuidString)")
        let descriptor = open(staged.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0o644)
        guard descriptor >= 0 else { throw Failure.recoveryRequired }
        defer { _ = unlink(staged.path) }
        let marker = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        try marker.write(contentsOf: data)
        try marker.synchronize()
        guard link(staged.path, markerURL.path) == 0 else { throw Failure.recoveryRequired }
        try directory.synchronize()
        lock = directory
    }

    /// The framework has neither launched nor armed its installer during download.
    func cancelBeforeExtraction() {
        guard let lock else {
            return
        }
        defer { self.lock = nil }
        if unlink(markerURL.path) == 0 {
            try? lock.synchronize()
        }
    }

    func recover(teamID: String) -> Bool {
        var marker = stat()
        if lstat(markerURL.path, &marker) != 0 {
            return errno == ENOENT
        }
        guard
            let directory = try? lockDirectory(),
            lstat(markerURL.path, &marker) == 0,
            marker.st_mode & S_IFMT == S_IFREG,
            marker.st_size > 0, marker.st_size < Self.maxMarkerBytes,
            let data = try? Data(contentsOf: markerURL),
            let transaction = try? JSONDecoder().decode(Transaction.self, from: data),
            let boot = Self.bootSession(),
            let values = Bundle(url: hostURL)?.infoDictionary,
            let version = values["CFBundleVersion"] as? String,
            version == transaction.version || boot != transaction.boot,
            verifyBundle(teamID: teamID),
            unlink(markerURL.path) == 0
        else {
            return false
        }
        try? directory.synchronize()
        return true
    }

    private func lockDirectory() throws -> FileHandle {
        let descriptor = open(parentURL.path, O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw Failure.unsupportedLocation }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            let busy = errno == EWOULDBLOCK
            close(descriptor)
            throw busy ? Failure.busy : Failure.unsupportedLocation
        }
        return FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }

    private func verifyBundle(teamID: String) -> Bool {
        guard teamID.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil else {
            return false
        }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(hostURL as CFURL, [], &code) == errSecSuccess, let code else {
            return false
        }
        var requirement: SecRequirement?
        let expression = """
        anchor apple generic and certificate leaf[subject.OU] = "\(teamID)" and identifier "com.kovyrin.agent-secret"
        """
        guard SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess else {
            return false
        }
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckNestedCode | kSecCSCheckAllArchitectures)
        return SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess
    }
}
