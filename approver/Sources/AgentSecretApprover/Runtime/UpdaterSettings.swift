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

    /// Whether the user opted in to background checks.
    public static var checksRequested: Bool {
        CFPreferencesCopyAppValue(enabledKey as CFString, preferencesDomain as CFString) as? Bool == true
    }

    /// The operating system's current disposition of the login item.
    public static var registrationStatus: SMAppService.Status {
        service.status
    }

    /// Updates the user's preference and registers or removes the login item.
    public static func setAutomaticChecks(_ enabled: Bool) throws {
        savePreference(enabled)
        if !enabled {
            try unregister()
            return
        }
        do {
            if service.status == .notRegistered || service.status == .notFound {
                try service.register()
            }
        } catch {
            savePreference(false)
            throw error
        }
    }

    /// Removes the login item before uninstall or app replacement.
    public static func unregister() throws {
        if service.status == .enabled || service.status == .requiresApproval {
            try service.unregister()
        }
    }

    private static func savePreference(_ enabled: Bool) {
        let domain = preferencesDomain as CFString
        CFPreferencesSetAppValue(enabledKey as CFString, enabled ? kCFBooleanTrue : kCFBooleanFalse, domain)
        CFPreferencesAppSynchronize(domain)
    }
}
