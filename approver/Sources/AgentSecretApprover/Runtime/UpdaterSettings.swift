import Darwin
import Foundation
import ServiceManagement

/// The user's update preference and the associated macOS login item.
public enum UpdaterSettings {
    private static let enabledKey = "AgentSecretAutomaticUpdateChecks"
    private static let preferencesDomain = "com.kovyrin.agent-secret.update-preferences"
    private static let identifier = "com.kovyrin.agent-secret.updater"

    private static var service: SMAppService {
        .loginItem(identifier: identifier)
    }

    private static var settings: AutomaticUpdateChecks {
        AutomaticUpdateChecks(
            readPreference: {
                CFPreferencesCopyAppValue(enabledKey as CFString, preferencesDomain as CFString) as? Bool
            },
            writePreference: savePreference,
            registrationStatus: { service.status },
            register: {
                try withUpdateRegistrationLease(at: Bundle.main.bundleURL) { try service.register() }
            },
            unregister: { try service.unregister() }
        )
    }

    /// Checks are on by default; an explicit opt-out remains off.
    public static var checksRequested: Bool {
        settings.checksRequested
    }

    /// The operating system's current disposition of the login item.
    public static var registrationStatus: SMAppService.Status {
        service.status
    }

    /// Development builds without a configured feed must not add a login item.
    public static var isConfigured: Bool {
        guard
            let feed = Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") as? String,
            let team = Bundle.main.object(forInfoDictionaryKey: "AgentSecretExpectedTeamID") as? String
        else {
            return false
        }
        return !feed.isEmpty && !team.isEmpty && team != "-"
    }

    /// Reconciles registration without changing the saved choice or macOS approval.
    public static func bootstrapAutomaticChecks() throws {
        guard isConfigured else {
            return
        }
        try settings.bootstrap()
    }

    /// Updates the user's preference and registers or removes the login item.
    public static func setAutomaticChecks(_ enabled: Bool) throws {
        try settings.setAutomaticChecks(enabled)
    }

    /// Removes the login item before uninstall or app replacement.
    public static func unregister() throws {
        try settings.removeRegistration()
    }

    private static func savePreference(_ enabled: Bool) {
        let domain = preferencesDomain as CFString
        CFPreferencesSetAppValue(enabledKey as CFString, enabled ? kCFBooleanTrue : kCFBooleanFalse, domain)
        CFPreferencesAppSynchronize(domain)
    }
}

func withUpdateRegistrationLease(at app: URL, registration: () throws -> Void) throws {
    let parent = app.deletingLastPathComponent()
    let descriptor = open(parent.path, O_RDONLY | O_CLOEXEC)
    guard descriptor >= 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    defer { close(descriptor) }
    guard flock(descriptor, LOCK_SH | LOCK_NB) == 0 else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EBUSY)
    }
    var marker = stat()
    let markerPath = parent.appendingPathComponent(".agent-secret-update").path
    guard lstat(markerPath, &marker) != 0, errno == ENOENT else {
        throw POSIXError(.EBUSY)
    }
    try registration()
}
