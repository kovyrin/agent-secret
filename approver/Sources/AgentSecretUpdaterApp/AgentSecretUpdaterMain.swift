import AgentSecretApprover
import AppKit
import OSLog
import ServiceManagement
import Sparkle

@main
@MainActor
final class AgentSecretUpdaterMain: NSObject, NSApplicationDelegate, SPUUpdaterDelegate {
    private static let log = Logger(subsystem: "com.kovyrin.agent-secret", category: "updater")
    private static let hostCommandTimeout: TimeInterval = 5
    private let updateReminders = GentleUpdateDelegate()
    private var updater: SPUUpdater?
    private var feedURL: String?
    private var manualCheck = false
    private var waitWindow: NSAlert?
    private var waiting = false
    private var barrier: InstallationBarrier?
    private var automaticChecksEnabled: Bool {
        UpdaterSettings.checksRequested && Self.hostRegistrationStatus() == SMAppService.Status.enabled.rawValue
    }

    static func main() {
        if CommandLine.arguments.dropFirst().elementsEqual(["--health-check"]) {
            let version = Bundle(for: SPUUpdater.self).object(forInfoDictionaryKey: "CFBundleShortVersionString")
            print("Agent Secret updater: Sparkle \(version ?? "unknown")")
            return
        }
        if CommandLine.arguments.dropFirst().elementsEqual(["--background-updater-status"]) {
            print(hostRegistrationStatus() ?? SMAppService.Status.notFound.rawValue)
            return
        }
        if CommandLine.arguments.dropFirst().elementsEqual(["--quiesce-for-package-manager"]) {
            let host = hostBundle()
            guard
                let host,
                let team = host.object(forInfoDictionaryKey: "AgentSecretExpectedTeamID") as? String,
                !team.isEmpty, team != "-",
                (try? SocketDaemonClient.quiesceForUpdate(hostBundle: host.bundleURL, expectedTeamID: team)) == true
            else {
                exit(1)
            }
            return
        }
        let application = NSApplication.shared
        let delegate = AgentSecretUpdaterMain()
        application.setActivationPolicy(.accessory)
        application.delegate = delegate
        application.run()
    }

    private static func hostBundle() -> Bundle? {
        let hostURL = Bundle.main.bundleURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        guard let host = Bundle(url: hostURL), host.bundleIdentifier == "com.kovyrin.agent-secret" else {
            return nil
        }
        return host
    }

    /// SMAppService resolves the login item in the outer app's context.
    /// Running the lookup in the nested helper itself reports .notFound.
    private static func hostRegistrationStatus() -> Int? {
        guard let text = runHostCommand("--background-updater-status") else {
            return nil
        }
        return Int(text.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private static func runHostCommand(_ argument: String) -> String? {
        guard let executable = hostBundle()?.executableURL else {
            return nil
        }
        let status = Process()
        let output = Pipe()
        status.executableURL = executable
        status.arguments = [argument]
        status.environment = [:]
        status.standardOutput = output
        status.standardError = FileHandle.nullDevice
        let finished = DispatchSemaphore(value: 0)
        status.terminationHandler = { _ in finished.signal() }
        do {
            try status.run()
        } catch {
            return nil
        }
        guard finished.wait(timeout: .now() + hostCommandTimeout) == .success else {
            status.terminate()
            return nil
        }
        guard status.terminationStatus == 0 else {
            return nil
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        guard let text = String(bytes: data, encoding: .utf8) else {
            return nil
        }
        return text
    }

    func applicationDidFinishLaunching(_: Notification) {
        guard
            let host = Self.hostBundle(),
            let feed = host.object(forInfoDictionaryKey: "SUFeedURL") as? String,
            let team = host.object(forInfoDictionaryKey: "AgentSecretExpectedTeamID") as? String,
            !team.isEmpty, team != "-"
        else {
            NSApp.terminate(nil)
            return
        }
        let hostURL = host.bundleURL
        feedURL = feed
        manualCheck = CommandLine.arguments.contains("--check-for-updates")
        let barrier = InstallationBarrier(hostURL: hostURL)
        self.barrier = barrier
        guard barrier.recover(teamID: team) else {
            if manualCheck {
                showMessage(
                    title: "Agent Secret Update Recovery",
                    body: """
                    An installation may still be running. If this message persists, restart your Mac
                    and open Check for Updates again. Reinstall the signed app if it cannot open.
                    """
                )
            }
            NSApp.terminate(nil)
            return
        }
        if Self.runHostCommand("--restore-background-updater") == nil {
            Self.log.info("Could not start background update checks; keeping the saved preference")
        }
        let driver = GatedUpdateDriver(hostBundle: host, delegate: updateReminders)
        driver.authorizeInstallation = { [weak self] item in
            await self?.authorizeInstallation(item, hostURL: hostURL, teamID: team) ?? false
        }
        driver.abandonDownload = { [weak barrier] in barrier?.cancelBeforeExtraction() }
        let updater = SPUUpdater(hostBundle: host, applicationBundle: .main, userDriver: driver, delegate: self)
        configureUpdater(updater)
        do {
            try updater.start()
            self.updater = updater
        } catch {
            NSApp.terminate(nil)
            return
        }
        if manualCheck {
            updater.checkForUpdates()
        } else if !automaticChecksEnabled {
            NSApp.terminate(nil)
        }
    }

    func applicationShouldHandleReopen(_: NSApplication, hasVisibleWindows _: Bool) -> Bool {
        manualCheck = true
        updater?.checkForUpdates()
        return false
    }

    private func configureUpdater(_ updater: SPUUpdater) {
        updateReminders.presentDeferredReminder = { [weak updater] in updater?.checkForUpdates() }
        updater.automaticallyDownloadsUpdates = false
        updater.sendsSystemProfile = false
        updater.automaticallyChecksForUpdates = automaticChecksEnabled
    }

    func feedURLString(for _: SPUUpdater) -> String? {
        feedURL
    }

    func updater(_: SPUUpdater, didFinishUpdateCycleFor _: SPUUpdateCheck, error: (any Error)?) {
        if error != nil {
            Self.log.info("Update check or installation ended with an error")
        }
        if !automaticChecksEnabled, waitWindow == nil {
            NSApp.terminate(nil)
        }
    }

    private func authorizeInstallation(_ item: SUAppcastItem, hostURL: URL, teamID: String) async -> Bool {
        guard let barrier, !item.isInformationOnlyUpdate, item.signingValidationStatus == .succeeded else {
            return false
        }
        do {
            try barrier.verifyLocation()
            showWaitingWindow()
            defer { closeWaitingWindow() }
            while waiting, !Task.isCancelled {
                let idle = try await Task.detached {
                    try SocketDaemonClient.quiesceForUpdate(hostBundle: hostURL, expectedTeamID: teamID)
                }.value
                if idle, waiting, !Task.isCancelled {
                    do {
                        try barrier.begin(version: item.versionString)
                        return true
                    } catch InstallationBarrier.Failure.busy {
                        // Another client or installer has the bundle. Retry with the same consent.
                    }
                }
                try await Task.sleep(for: .seconds(1))
            }
        } catch is CancellationError {
            return false
        } catch InstallationBarrier.Failure.unsupportedLocation {
            showMessage(
                title: "Agent Secret Cannot Update Here",
                body: "Copy Agent Secret into a writable Applications folder or upgrade it with Homebrew."
            )
        } catch {
            showMessage(
                title: "Agent Secret Could Not Prepare the Update",
                body: "Check that this is your installed copy. Close any other copy of Agent Secret and try again."
            )
        }
        return false
    }

    private func showWaitingWindow() {
        let alert = NSAlert()
        alert.messageText = "Waiting to Install Agent Secret"
        alert.informativeText = """
        Installation will start when Agent Secret has no pending approvals, running commands, or live sessions.
        Brokers in other accounts and another installer can also delay the update.
        """
        let cancel = alert.addButton(withTitle: "Cancel")
        cancel.target = self
        cancel.action = #selector(cancelWaiting)
        waiting = true
        waitWindow = alert
        alert.window.makeKeyAndOrderFront(nil)
    }

    @objc
    private func cancelWaiting() {
        closeWaitingWindow()
    }

    private func closeWaitingWindow() {
        waiting = false
        waitWindow?.window.orderOut(nil)
        waitWindow = nil
    }

    private func showMessage(title: String, body: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = body
        alert.runModal()
    }
}
