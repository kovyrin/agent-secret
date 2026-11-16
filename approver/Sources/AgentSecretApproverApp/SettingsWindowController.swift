import AppKit

@MainActor
final class SettingsWindowController: NSWindowController {
    private enum Metric {
        static let width: CGFloat = 500
        static let height: CGFloat = 350
        static let noticeHeight: CGFloat = 380
        static let iconSide: CGFloat = 44
        static let titleSize: CGFloat = 16
        static let captionSize: CGFloat = 11
        static let statusSize: CGFloat = 12
        static let identityGap: CGFloat = 3
        static let rowGap: CGFloat = 12
        static let statusGap: CGFloat = 5
        static let controlGap: CGFloat = 7
        static let sectionGap: CGFloat = 16
        static let footerGap: CGFloat = 8
        static let margin: CGFloat = 26
        static let top: CGFloat = 22
        static let bottom: CGFloat = 18
        static let progressSide: CGFloat = 16
        static let noticeLines = 2
    }

    var onInstall: (() -> Void)?
    var onDiagnostics: (() -> Void)?
    var onCheckForUpdates: (() -> Void)?
    var onAutomaticChecks: ((Bool) -> Void)?

    private let cliStatus = NSTextField(labelWithString: "")
    private let install = NSButton(title: "", target: nil, action: nil)
    private let automaticChecks = NSButton(
        checkboxWithTitle: "Check for updates automatically", target: nil, action: nil
    )
    private let updateNotice = NSTextField(wrappingLabelWithString: "")
    private let check = NSButton(title: "Check for Updates…", target: nil, action: nil)
    private let diagnostics = NSButton(title: "Run Diagnostics…", target: nil, action: nil)
    private let activity = NSTextField(labelWithString: "")
    private let progress = NSProgressIndicator()

    init(state: SettingsState, icon: NSImage?) {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: Metric.width, height: Metric.height),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "Agent Secret Settings"
        window.isReleasedWhenClosed = false
        window.isRestorable = false
        super.init(window: window)
        buildContent(version: state.version, icon: icon)
        connectActions()
        update(state)
        window.center()
    }

    @available(*, unavailable)
    required init?(coder _: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func update(_ state: SettingsState) {
        cliStatus.stringValue = state.cli.description
        install.title = state.cli.action
        install.isEnabled = !state.busy && state.cli != .unavailable
        automaticChecks.state = state.automaticChecks ? .on : .off
        automaticChecks.isEnabled = !state.busy && state.updatesConfigured
        check.isEnabled = !state.busy && state.updatesConfigured
        diagnostics.isEnabled = !state.busy
        updateNotice.stringValue = state.updatesConfigured
            ? state.updateNotice : "Updates are unavailable for this build."
        activity.stringValue = state.activity
        progress.isHidden = !state.busy
        if state.busy {
            progress.startAnimation(nil)
        } else {
            progress.stopAnimation(nil)
        }
        let height = updateNotice.stringValue.isEmpty ? Metric.height : Metric.noticeHeight
        window?.setContentSize(NSSize(width: Metric.width, height: height))
    }

    private func buildContent(version: String, icon: NSImage?) {
        guard let content = window?.contentView else {
            return
        }
        let firstLine = separator()
        let secondLine = separator()
        let thirdLine = separator()
        let cli = cliRow()
        let updates = updatesSection()
        let footer = footerRow()
        let body = stack(
            [header(version: version, icon: icon), firstLine, cli, secondLine, updates, thirdLine, footer],
            spacing: Metric.sectionGap
        )
        body.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(body)
        NSLayoutConstraint.activate([
            body.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: Metric.margin),
            body.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -Metric.margin),
            body.topAnchor.constraint(equalTo: content.topAnchor, constant: Metric.top),
            body.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -Metric.bottom)
        ])
        for row in [firstLine, cli, secondLine, updates, thirdLine, footer] {
            row.widthAnchor.constraint(equalTo: body.widthAnchor).isActive = true
        }
    }

    private func header(version: String, icon: NSImage?) -> NSView {
        let identity = NSImageView(image: icon ?? NSImage(named: NSImage.applicationIconName) ?? NSImage())
        identity.imageScaling = .scaleProportionallyUpOrDown
        identity.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            identity.widthAnchor.constraint(equalToConstant: Metric.iconSide),
            identity.heightAnchor.constraint(equalToConstant: Metric.iconSide)
        ])
        let name = label("Agent Secret", size: Metric.titleSize, weight: .semibold)
        let versionLabel = label("Version \(version)", size: Metric.captionSize, secondary: true)
        return stack(
            [identity, stack([name, versionLabel], spacing: Metric.identityGap)],
            spacing: Metric.rowGap,
            axis: .horizontal
        )
    }

    private func cliRow() -> NSView {
        cliStatus.font = .systemFont(ofSize: Metric.statusSize)
        cliStatus.textColor = .secondaryLabelColor
        let cli = stack([label("Command-line tool", weight: .semibold), cliStatus], spacing: Metric.statusGap)
        return stack([cli, NSView(), install], spacing: Metric.rowGap, axis: .horizontal)
    }

    private func updatesSection() -> NSView {
        let help = label("You approve every installation.", size: Metric.captionSize, secondary: true)
        let updates = stack([label("Updates", weight: .semibold), automaticChecks, help], spacing: Metric.controlGap)
        updateNotice.font = .systemFont(ofSize: Metric.captionSize)
        updateNotice.textColor = .secondaryLabelColor
        updateNotice.maximumNumberOfLines = Metric.noticeLines
        updateNotice.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let actions = stack([check, updateNotice], spacing: Metric.rowGap, axis: .horizontal)
        updates.addArrangedSubview(actions)
        actions.widthAnchor.constraint(equalTo: updates.widthAnchor).isActive = true
        updates.setCustomSpacing(Metric.rowGap, after: help)
        return updates
    }

    private func footerRow() -> NSView {
        progress.style = .spinning
        progress.controlSize = .small
        progress.isDisplayedWhenStopped = false
        progress.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            progress.widthAnchor.constraint(equalToConstant: Metric.progressSide),
            progress.heightAnchor.constraint(equalToConstant: Metric.progressSide)
        ])
        activity.font = .systemFont(ofSize: Metric.captionSize)
        activity.textColor = .secondaryLabelColor
        activity.lineBreakMode = .byTruncatingTail
        return stack(
            [label("Diagnostics", weight: .semibold), NSView(), progress, activity, diagnostics],
            spacing: Metric.footerGap,
            axis: .horizontal
        )
    }

    private func connectActions() {
        for button in [install, check, diagnostics] {
            button.bezelStyle = .rounded
        }
        install.target = self
        install.action = #selector(installCLI)
        diagnostics.target = self
        diagnostics.action = #selector(runDiagnostics)
        automaticChecks.target = self
        automaticChecks.action = #selector(changeAutomaticChecks)
        check.target = self
        check.action = #selector(checkForUpdates)
    }

    @objc
    private func installCLI() {
        onInstall?()
    }

    @objc
    private func runDiagnostics() {
        onDiagnostics?()
    }

    @objc
    private func checkForUpdates() {
        onCheckForUpdates?()
    }

    @objc
    private func changeAutomaticChecks() {
        onAutomaticChecks?(automaticChecks.state == .on)
    }

    private func label(
        _ text: String,
        size: CGFloat = NSFont.systemFontSize,
        weight: NSFont.Weight = .regular,
        secondary: Bool = false
    ) -> NSTextField {
        let field = NSTextField(labelWithString: text)
        field.font = .systemFont(ofSize: size, weight: weight)
        field.textColor = secondary ? .secondaryLabelColor : .labelColor
        return field
    }

    private func stack(
        _ views: [NSView], spacing: CGFloat, axis: NSUserInterfaceLayoutOrientation = .vertical
    ) -> NSStackView {
        let stack = NSStackView(views: views)
        stack.orientation = axis
        stack.alignment = axis == .vertical ? .leading : .centerY
        stack.spacing = spacing
        return stack
    }

    private func separator() -> NSBox {
        let line = NSBox()
        line.boxType = .separator
        return line
    }
}
