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
    @MainActor
    private func showSetupResult(title: String, message: String, style: NSAlert.Style) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = style
        alert.addButton(withTitle: "Close")
        alert.runModal()
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
