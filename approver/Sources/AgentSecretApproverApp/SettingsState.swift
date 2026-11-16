import Foundation

struct SettingsState {
    enum CLIStatus {
        case installed
        case missing
        case repairNeeded
        case unavailable

        var description: String {
            switch self {
            case .installed:
                "Installed"

            case .missing:
                "Not installed"

            case .repairNeeded:
                "Repair needed"

            case .unavailable:
                "App needs reinstalling"
            }
        }

        var action: String {
            self == .missing ? "Install…" : "Repair…"
        }
    }

    var version: String
    var cli: CLIStatus
    var updatesConfigured: Bool
    var automaticChecks: Bool
    var updateNotice = ""
    var activity = ""
    var busy = false
}
