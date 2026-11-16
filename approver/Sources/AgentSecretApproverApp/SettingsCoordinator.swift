import AgentSecretApprover
import AppKit

@MainActor
final class SettingsCoordinator {
    private static let hostTimeout: TimeInterval = 5
    private static let cliTimeout: TimeInterval = 20
    private(set) var state: SettingsState
    let controller: SettingsWindowController
    private var details: SettingsDetailsController?
    private let readState: @MainActor () -> SettingsState
    private let runCLI: ([String], TimeInterval) async -> SettingsCommandRunner.Result
    private let runHost: ([String], TimeInterval) async -> SettingsCommandRunner.Result

    init(
        readState: @escaping @MainActor () -> SettingsState = SettingsState.current,
        runCLI: @escaping ([String], TimeInterval) async -> SettingsCommandRunner.Result = { arguments, timeout in
            await SettingsCommandRunner.run(executable: SettingsCLI.executable, arguments: arguments, timeout: timeout)
        },
        runHost: @escaping ([String], TimeInterval) async -> SettingsCommandRunner.Result = { arguments, timeout in
            guard let executable = Bundle.main.executableURL else {
                return SettingsCommandRunner.Result(
                    output: "Reinstall Agent Secret to restore updates.",
                    succeeded: false
                )
            }
            return await SettingsCommandRunner.run(executable: executable, arguments: arguments, timeout: timeout)
        }
    ) {
        self.readState = readState
        self.runCLI = runCLI
        self.runHost = runHost
        state = readState()
        controller = SettingsWindowController(state: state, icon: nil)
        controller.onInstall = { [weak self] in Task { await self?.installCLI() } }
        controller.onDiagnostics = { [weak self] in Task { await self?.runDiagnostics() } }
        controller.onCheckForUpdates = { [weak self] in Task { await self?.checkForUpdates() } }
        controller.onAutomaticChecks = { [weak self] enabled in Task { await self?.setAutomaticChecks(enabled) } }
    }

    func refresh() {
        guard !state.busy else {
            return
        }
        state = readState()
        controller.update(state)
    }

    func bootstrap() async {
        guard state.updatesConfigured, state.automaticChecks else {
            return
        }
        await perform(
            title: "Starting update checks…",
            arguments: ["--restore-background-updater"],
            timeout: Self.hostTimeout,
            host: true,
            quietFailure: true
        )
    }

    func installCLI() async {
        await perform(
            title: "Installing command-line tool…",
            arguments: ["install-cli"],
            timeout: Self.cliTimeout,
            detailsTitle: "Command-line Tool"
        )
    }

    func runDiagnostics() async {
        await perform(
            title: "Running diagnostics…",
            arguments: ["doctor"],
            timeout: Self.cliTimeout,
            detailsTitle: "Diagnostics"
        )
    }

    func checkForUpdates() async {
        await perform(title: "Opening updater…", arguments: ["update", "check"], timeout: Self.hostTimeout)
    }

    func setAutomaticChecks(_ enabled: Bool) async {
        await perform(
            title: "Saving update preference…",
            arguments: [enabled ? "--enable-automatic-update-checks" : "--disable-automatic-update-checks"],
            timeout: Self.hostTimeout,
            host: true
        )
    }

    private func perform(
        title: String,
        arguments: [String],
        timeout: TimeInterval,
        host: Bool = false,
        detailsTitle: String? = nil,
        quietFailure: Bool = false
    ) async {
        guard !state.busy else {
            return
        }
        state.busy = true
        state.activity = title
        controller.update(state)
        let result = await (host ? runHost : runCLI)(arguments, timeout)
        state = readState()
        state.activity = result.succeeded || quietFailure ? "" : "Action failed. See details."
        if quietFailure, !result.succeeded {
            state.updateNotice = "Background checks need attention. Reopen Settings to retry."
        }
        controller.update(state)
        if let detailsTitle {
            showDetails(title: detailsTitle, result: result)
        } else if !result.succeeded, !quietFailure {
            showDetails(title: "Agent Secret", result: result)
        }
    }

    private func showDetails(title: String, result: SettingsCommandRunner.Result) {
        guard let parent = controller.window, parent.isVisible, parent.attachedSheet == nil else {
            return
        }
        let details = SettingsDetailsController(
            title: title, summary: result.succeeded ? "Completed" : "Some checks need attention", output: result.output
        )
        self.details = details
        if let window = details.window { parent.beginSheet(window) }
    }
}

extension SettingsState {
    @MainActor
    static func current() -> Self {
        var state = Self(
            version: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Development",
            cli: SettingsCLI.status,
            updatesConfigured: UpdaterSettings.isConfigured,
            automaticChecks: UpdaterSettings.checksRequested
        )
        if state.updatesConfigured, state.automaticChecks {
            switch UpdaterSettings.registrationStatus {
            case .requiresApproval:
                state.updateNotice = "Allow Agent Secret in System Settings → General → Login Items."

            case .enabled:
                break

            default:
                state.updateNotice = "Background checks need attention. Reopen Settings to retry."
            }
        }
        return state
    }
}
