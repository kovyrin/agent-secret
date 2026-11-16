import AgentSecretApprover
import AppKit

@MainActor
final class UpdatePreferencesView: NSStackView {
    private let automaticChecks = NSButton(
        checkboxWithTitle: "Check for updates automatically", target: nil, action: nil
    )
    private let status = NSTextField(labelWithString: "")

    init() {
        super.init(frame: .zero)
        orientation = .vertical
        alignment = .leading
        automaticChecks.target = self
        automaticChecks.action = #selector(changeAutomaticChecks)
        addArrangedSubview(automaticChecks)
        addArrangedSubview(status)
        let check = NSButton(title: "Check for Updates…", target: self, action: #selector(checkForUpdates))
        addArrangedSubview(check)
        refresh()
    }

    @available(*, unavailable)
    required init(coder _: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    @objc
    private func changeAutomaticChecks() {
        do {
            try UpdaterSettings.setAutomaticChecks(automaticChecks.state == .on)
            refresh()
        } catch {
            status.stringValue = "Could not change the background item. Try again in System Settings."
        }
    }

    @objc
    private func checkForUpdates() {
        let helper = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Library/LoginItems/AgentSecretUpdater.app")
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.arguments = ["--check-for-updates"]
        NSWorkspace.shared.openApplication(at: helper, configuration: configuration)
    }

    private func refresh() {
        automaticChecks.state = UpdaterSettings.checksRequested ? .on : .off
        if UpdaterSettings.checksRequested, UpdaterSettings.registrationStatus == .requiresApproval {
            status.stringValue = "Allow Agent Secret in System Settings → General → Login Items."
        } else {
            status.stringValue = "Agent Secret asks before installing each update."
        }
    }
}
