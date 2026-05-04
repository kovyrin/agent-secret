import Foundation

#if canImport(AppKit)
    import AppKit
#endif

@MainActor
func runSetupDialog() {
    #if canImport(AppKit)
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        NSRunningApplication.current.activate(options: [.activateAllWindows])

        var message = setupIntroText()
        var shouldContinue = true
        while shouldContinue {
            let alert = NSAlert()
            alert.messageText = "Agent Secret"
            alert.informativeText = message
            alert.alertStyle = .informational
            alert.addButton(withTitle: "Install Command Line Tool")
            alert.addButton(withTitle: "Run Diagnostics")
            alert.addButton(withTitle: "Quit")

            switch alert.runModal() {
            case .alertFirstButtonReturn:
                let result = runBundledAgentSecret(arguments: ["install-cli"])
                showSetupResult(
                    title: result.succeeded ? "Command Line Tool Installed" : "Command Line Tool Install Failed",
                    message: result.output,
                    style: result.succeeded ? .informational : .warning
                )
                if result.succeeded {
                    shouldContinue = false
                }

            case .alertSecondButtonReturn:
                message = runBundledAgentSecret(arguments: ["doctor"]).output

            default:
                shouldContinue = false
            }
        }
        app.terminate(nil)
    #else
        /* AppKit is required for the setup dialog. */
    #endif
}

private func setupIntroText() -> String {
    """
    Agent Secret is installed as a macOS app with the command-line tool bundled inside it.

    Install Command Line Tool creates or repairs the agent-secret command symlink for this user.
    Run Diagnostics prints non-secret local setup information.
    """
}

#if canImport(AppKit)
    private let kSetupTerminalCommandWidth: CGFloat = 620
    private let kSetupTerminalCommandPadding: CGFloat = 12
    private let kSetupTerminalCommandFontSize: CGFloat = 12
    private let kSetupTerminalBackgroundWhite: CGFloat = 0.07
    private let kSetupTerminalBorderWhite: CGFloat = 0.22
    private let kSetupTerminalBorderWidth: CGFloat = 1
    private let kSetupTerminalCornerRadius: CGFloat = 8
    private let kSetupTerminalTextWhite: CGFloat = 0.92
    private let kSetupTerminalMinimumTextHeight: CGFloat = 42
    private let kSetupTerminalMaximumTextHeight: CGFloat = 180
    private let kSetupTerminalFrameOrigin: CGFloat = 0
    private let kSetupTerminalOpaqueAlpha: CGFloat = 1
    private let kSetupTerminalPaddingMultiplier: CGFloat = 2
    private let kSetupTerminalUnlimitedLines = 0

    @MainActor
    private func showSetupResult(title: String, message: String, style: NSAlert.Style) {
        let result = formattedSetupResult(message)
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = result.body
        alert.alertStyle = style
        if let command = result.command {
            alert.accessoryView = terminalCommandView(command)
        }
        alert.addButton(withTitle: "Close")
        alert.runModal()
    }

    private func formattedSetupResult(_ message: String) -> (body: String, command: String?) {
        let marker = "For zsh, run this one-liner:"
        guard let markerRange = message.range(of: marker) else {
            return (message, nil)
        }

        var body = String(message[..<markerRange.upperBound]).trimmingCharacters(in: .whitespacesAndNewlines)
        let command = message[markerRange.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
        if body.hasPrefix("agent-secret command installed: ") {
            body = replacingFirstLine(in: body, with: "agent-secret command installed.")
        }
        body = body.replacingOccurrences(of: "`agent-secret`", with: "agent-secret")
        return (body, command.isEmpty ? nil : command)
    }

    @MainActor
    private func terminalCommandView(_ command: String) -> NSView {
        let width = kSetupTerminalCommandWidth
        let padding = kSetupTerminalCommandPadding
        let font = NSFont.monospacedSystemFont(ofSize: kSetupTerminalCommandFontSize, weight: .regular)
        let textWidth = width - padding * kSetupTerminalPaddingMultiplier
        let textHeight = terminalTextHeight(command, font: font, width: textWidth)
        let height = textHeight + padding * kSetupTerminalPaddingMultiplier

        let container = NSView(
            frame: NSRect(
                x: kSetupTerminalFrameOrigin,
                y: kSetupTerminalFrameOrigin,
                width: width,
                height: height
            )
        )
        container.wantsLayer = true
        container.layer?.backgroundColor = terminalColor(kSetupTerminalBackgroundWhite).cgColor
        container.layer?.borderColor = terminalColor(kSetupTerminalBorderWhite).cgColor
        container.layer?.borderWidth = kSetupTerminalBorderWidth
        container.layer?.cornerRadius = kSetupTerminalCornerRadius

        let commandField = NSTextField(wrappingLabelWithString: command)
        commandField.frame = NSRect(x: padding, y: padding, width: textWidth, height: textHeight)
        commandField.autoresizingMask = [.width, .height]
        commandField.font = font
        commandField.isSelectable = true
        commandField.lineBreakMode = .byCharWrapping
        commandField.maximumNumberOfLines = kSetupTerminalUnlimitedLines
        commandField.textColor = terminalColor(kSetupTerminalTextWhite)
        container.addSubview(commandField)

        return container
    }

    private func terminalTextHeight(_ text: String, font: NSFont, width: CGFloat) -> CGFloat {
        let attributed = NSAttributedString(string: text, attributes: [.font: font])
        let rect = attributed.boundingRect(
            with: NSSize(width: width, height: CGFloat.greatestFiniteMagnitude),
            options: [.usesLineFragmentOrigin, .usesFontLeading]
        )
        return min(max(ceil(rect.height), kSetupTerminalMinimumTextHeight), kSetupTerminalMaximumTextHeight)
    }

    private func replacingFirstLine(in text: String, with replacement: String) -> String {
        guard let newline = text.firstIndex(of: "\n") else {
            return replacement
        }
        return replacement + text[newline...]
    }

    private func terminalColor(_ white: CGFloat) -> NSColor {
        NSColor(calibratedWhite: white, alpha: kSetupTerminalOpaqueAlpha)
    }
#endif

private func runBundledAgentSecret(arguments: [String]) -> (output: String, succeeded: Bool) {
    guard let cliPath = bundledAgentSecretPath() else {
        return ("""
        The bundled agent-secret command was not found inside this app.

        Reinstall Agent Secret.app, then open the app again.
        """, false)
    }

    let process = Process()
    process.executableURL = URL(fileURLWithPath: cliPath)
    process.arguments = arguments

    let outputPipe = Pipe()
    process.standardOutput = outputPipe
    process.standardError = outputPipe

    do {
        try process.run()
        process.waitUntilExit()
    } catch {
        return ("Could not run \(cliPath): \(error)", false)
    }

    let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
    let output = (String(bytes: data, encoding: .utf8) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    if process.terminationStatus == 0 {
        return (output.isEmpty ? "Command completed." : output, true)
    }
    if output.isEmpty {
        let command = arguments.joined(separator: " ")
        return ("agent-secret \(command) failed with exit \(process.terminationStatus).", false)
    }
    return (output, false)
}

private func bundledAgentSecretPath() -> String? {
    let candidate = URL(fileURLWithPath: Bundle.main.bundlePath)
        .appendingPathComponent("Contents")
        .appendingPathComponent("Resources")
        .appendingPathComponent("bin")
        .appendingPathComponent("agent-secret")
        .path

    return FileManager.default.isExecutableFile(atPath: candidate) ? candidate : nil
}
